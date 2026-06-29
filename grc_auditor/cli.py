"""Orchestration + CLI entrypoint.

Wires the pipeline end-to-end:
    discover -> classify -> (reach -> detect -> scan)* -> persist -> report

Per-host work (reach/detect/scan) runs in a bounded thread pool (IO-bound SSH),
capped by scope.ssh_concurrency. Discovery and reporting are single-shot.
"""

from __future__ import annotations

import argparse
import os
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
    return datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")


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

    run_id = _run_id()
    run_dir = os.path.join(cfg.output_dir, "runs", run_id)
    log = setup_logging(run_dir, verbose=args.verbose)
    log.info("grc-auditor %s | run %s", __version__, run_id)
    log.info("AUTHORIZATION: scanning scope %s - operator asserts authorization",
             ", ".join(cfg.scope.cidrs))

    run = RunRecord(run_id=run_id, started_at=_utcnow(),
                    scope=list(cfg.scope.cidrs), config_hash=cfg.hash())

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

    if args.dry_run:
        log.info("dry-run: %d host(s) would be deep-scanned; skipping SSH/scan",
                 len(candidates))
    else:
        # Stage 4-6: reach + detect + scan, bounded concurrency
        store_artifacts = os.path.join(cfg.output_dir, "runs")
        log.info("processing %d candidate host(s) with concurrency %d",
                 len(candidates), cfg.scope.ssh_concurrency)
        with ThreadPoolExecutor(max_workers=cfg.scope.ssh_concurrency) as pool:
            futures = {
                pool.submit(_process_host, h, cfg, run_id, store_artifacts): h
                for h in candidates
            }
            for fut in as_completed(futures):
                fut.result()  # _process_host never raises

    run.finished_at = _utcnow()

    # Stage 7: persist
    store = Store(cfg.output_dir)
    try:
        store.save_run(run)
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
    print()
    print(f"Run {run.run_id} complete.")
    print(f"  Hosts discovered : {len(run.hosts)}")
    print(f"  Scanned          : {counts.get('scanned', 0)}")
    print(f"  Coverage gaps    : {len(run.coverage_gaps())}")
    print(f"  Fleet pass rate  : {pr if pr is not None else 'n/a'}"
          + ("%" if pr is not None else ""))
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
    print(f"{'RUN ID':<20}  {'STARTED':<22}  SCOPE")
    for r in runs:
        scope = ", ".join(__import__("json").loads(r["scope"] or "[]"))
        print(f"{r['run_id']:<20}  {r['started_at']:<22}  {scope}")
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
