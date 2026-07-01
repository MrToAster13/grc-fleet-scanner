"""Orchestration + CLI entrypoint.

Wires the pipeline end-to-end:
    discover -> classify -> (reach -> detect -> scan)* -> persist -> report

Per-host work (reach/detect/scan) runs in a bounded thread pool (IO-bound SSH),
capped by scope.ssh_concurrency. Discovery and reporting are single-shot.
"""

from __future__ import annotations

import argparse
import json
import os
import secrets
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone

from . import __version__, discovery, classify as classify_mod
from .config import (
    Config, ConfigError, apply_overrides, ip_in_networks, load_config,
)
from .detect import detect
from .logging_setup import get_logger, setup_logging
from .models import HostRecord, HostStatus, RunRecord
from .remote import HostKeyMismatch, RemoteError, RemoteHost
from .report import write_reports
from .scan import scan_host
from .store import Store


def _utcnow() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _run_id() -> str:
    # The timestamp prefix keeps run ids lexically sortable (history ordering and
    # previous_run_id rely on `run_id < ?` string comparison). The short random
    # suffix makes a collision between two runs started in the same wall-clock
    # second effectively impossible, so one run can never overwrite or be confused
    # with another's on-disk evidence.
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    return f"{stamp}-{secrets.token_hex(3)}"


def _process_host(host: HostRecord, cfg: Config, run_id: str,
                  artifacts_root: str) -> HostRecord:
    """Reach + detect + scan a single host. Never raises; encodes outcome in status."""
    log = get_logger()
    group = cfg.credential_group_for(host.ip)
    if group is None:  # defensive; classify should have caught this
        host.status = HostStatus.NO_CREDENTIALS
        host.detail = "no credential group matched"
        return host

    try:
        with RemoteHost(host.ip, group, cfg.known_hosts) as conn:
            plan = detect(host, conn, cfg)
            if plan is None:
                return host  # detect set an explanatory status
            try:
                scan_host(host, conn, plan, run_id, artifacts_root,
                          timeout=cfg.scope.host_timeout_seconds)
            except Exception as exc:  # scan_host sets status on known failures
                if host.status is not HostStatus.SCAN_ERROR:
                    host.status = HostStatus.SCAN_ERROR
                    host.detail = f"scan failed: {exc}"
                log.warning("scan[%s] failed: %s", host.ip, exc)
    except HostKeyMismatch as exc:
        # Distinct from plain unreachability: the host key no longer matches the
        # pinned key. Surfaced as a security finding (possible MITM / unverified
        # re-provisioning), not a coverage gap to shrug off.
        host.status = HostStatus.HOST_KEY_MISMATCH
        host.detail = str(exc)
        log.warning("reach[%s] HOST KEY MISMATCH: %s", host.ip, exc)
    except RemoteError as exc:
        host.status = HostStatus.UNREACHABLE
        host.detail = str(exc)
        log.warning("reach[%s] failed: %s", host.ip, exc)
    except Exception as exc:  # pragma: no cover - unexpected
        host.status = HostStatus.SCAN_ERROR
        host.detail = f"unexpected error: {exc}"
        log.exception("host[%s] unexpected error", host.ip)
    return host


def cmd_run(args) -> int:
    try:
        cfg = load_config(args.config)
        cfg = apply_overrides(
            cfg, cidrs=args.cidr, exclude=args.exclude, output_dir=args.output,
            cis_level=args.cis_level, ssh_concurrency=args.concurrency,
            low_confidence_threshold=args.low_confidence_threshold,
        )
    except ConfigError as exc:
        print(f"config error: {exc}", file=sys.stderr)
        return 2

    # Restrict permissions on everything this run creates (dirs 0700, files 0600).
    # The evidence/logs/report encode the fleet's full internal posture + scope; on
    # a shared jump host (the design's stated run host) default 0644/0755 would let
    # any other local user read it. umask is process-global and this is a one-shot
    # CLI, so setting it here covers makedirs + open + SFTP-written evidence.
    os.umask(0o077)

    run_id = _run_id()
    run_dir = os.path.join(cfg.output_dir, "runs", run_id)
    log = setup_logging(run_dir, verbose=args.verbose)
    log.info("grc-auditor %s | run %s", __version__, run_id)
    log.info("AUTHORIZATION: scanning scope %s - operator asserts authorization",
             ", ".join(cfg.scope.cidrs))

    run = RunRecord(run_id=run_id, started_at=_utcnow(),
                    scope=list(cfg.scope.cidrs), config_hash=cfg.hash())

    # Seal the effective (override-applied) configuration as run provenance; the
    # manifest hashes it too, and config_hash is derived from the same canonical
    # form, so the run is reproducible and self-describing.
    with open(os.path.join(run_dir, "effective-config.json"), "w",
              encoding="utf-8") as fh:
        json.dump(cfg.canonical(), fh, indent=2, sort_keys=True)

    # Stage 1-2: discover
    try:
        hosts = discovery.discover(cfg.scope, want_os=args.os_detect)
    except discovery.DiscoveryError as exc:
        log.error("discovery failed: %s", exc)
        return 1

    # Re-enforce exclusions before any SSH (defense in depth): nmap already gets
    # --exclude, but the golden rule is too important to rely on a single layer --
    # an excluded IP must never be connected to even if discovery returns it.
    if cfg.scope.exclude:
        kept = [h for h in hosts if not ip_in_networks(h.ip, cfg.scope.exclude)]
        if len(kept) != len(hosts):
            log.warning("dropped %d discovered host(s) matching scope.exclude "
                        "before any SSH", len(hosts) - len(kept))
        hosts = kept

    # Stage 3: classify
    classify_mod.classify(hosts, cfg)
    run.hosts = hosts

    candidates = [h for h in hosts if h.status is HostStatus.DISCOVERED]

    # Stage 7 persistence is now INCREMENTAL: the run row is written before any
    # SSH (so a crash leaves a visibly-incomplete run, not orphaned evidence), and
    # each host is persisted as it is finalized.
    store = Store(cfg.output_dir)
    try:
        store.begin_run(run)
        # Hosts already finalized by classify (non_ubuntu / no_credentials / ...)
        # are done -- persist them up front. The candidates (still DISCOVERED) are
        # persisted below as each finishes reach/detect/scan.
        for h in run.hosts:
            if h.status is not HostStatus.DISCOVERED:
                store.save_host(run.run_id, h)

        if args.dry_run:
            log.info("dry-run: %d host(s) would be deep-scanned; skipping SSH/scan",
                     len(candidates))
            for h in candidates:
                store.save_host(run.run_id, h)
        else:
            # Stage 4-6: reach + detect + scan, bounded concurrency. Workers do the
            # IO and return the host; the main thread persists each as it completes
            # (keeps the single SQLite connection thread-confined).
            log.info("processing %d candidate host(s) with concurrency %d",
                     len(candidates), cfg.scope.ssh_concurrency)
            with ThreadPoolExecutor(max_workers=cfg.scope.ssh_concurrency) as pool:
                futures = {
                    pool.submit(_process_host, h, cfg, run_id, store.artifacts_root): h
                    for h in candidates
                }
                for fut in as_completed(futures):
                    store.save_host(run.run_id, fut.result())  # never raises

        run.finished_at = _utcnow()
        store.finish_run(run.run_id, run.finished_at)

        # Stage 8: report (drift needs the store, after this run is saved)
        paths = write_reports(run, store, run_dir,
                              low_confidence_threshold=cfg.low_confidence_threshold)
    finally:
        store.close()

    _print_summary(run, paths)
    return 0


def _print_summary(run: RunRecord, paths: dict) -> None:
    counts = run.counts_by_status()
    pr = run.fleet_pass_rate()
    pr_str = f"{pr}%" if pr is not None else "n/a"
    print()
    print(f"Run {run.run_id} complete.")
    print(f"  Hosts discovered : {len(run.hosts)}")
    print(f"  Scanned          : {counts.get('scanned', 0)}")
    print(f"  Coverage gaps    : {len(run.coverage_gaps())}")
    print(f"  Fleet pass rate  : {pr_str}")
    print(f"  Report           : {paths['html']}")
    print(f"  JSON / CSV       : {paths['json']}")


def cmd_history(args) -> int:
    store = Store(args.output)
    try:
        runs = store.list_runs()
    finally:
        store.close()
    if not runs:
        print("No runs recorded yet.")
        return 0
    print(f"{'RUN ID':<24}  {'STARTED':<22}  SCOPE")
    for r in runs:
        scope = ", ".join(json.loads(r["scope"] or "[]"))
        print(f"{r['run_id']:<24}  {r['started_at']:<22}  {scope}")
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="grc-audit",
        description="Discover network hosts and audit Ubuntu hosts against the "
                    "CIS Benchmark via OpenSCAP.",
    )
    p.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    sub = p.add_subparsers(dest="command", required=True)

    r = sub.add_parser("run", help="run a fleet audit")
    r.add_argument("-c", "--config", required=True, help="path to YAML config")
    r.add_argument("--cidr", action="append", help="override scope CIDR (repeatable)")
    r.add_argument("--exclude", action="append", help="override exclusions (repeatable)")
    r.add_argument("-o", "--output", help="override output directory")
    r.add_argument("--cis-level", type=int, choices=(1, 2),
                   help="override global CIS level (default from config)")
    r.add_argument("--concurrency", type=int, help="override SSH concurrency")
    r.add_argument("--low-confidence-threshold", type=float, metavar="PCT",
                   help="flag a host's score LOW CONFIDENCE below this %% of the "
                        "benchmark producing a verdict (default 90)")
    r.add_argument("--os-detect", action="store_true",
                   help="enable nmap OS detection (-O, needs root on run host)")
    r.add_argument("--dry-run", action="store_true",
                   help="discover + classify only; no SSH, no scanning")
    r.add_argument("-v", "--verbose", action="store_true")
    r.set_defaults(func=cmd_run)

    h = sub.add_parser("history", help="list prior runs")
    h.add_argument("-o", "--output", default="./grc-output",
                   help="output directory holding history.db")
    h.set_defaults(func=cmd_history)

    return p


def main(argv=None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
