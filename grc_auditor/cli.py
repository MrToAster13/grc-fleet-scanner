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


def _example_config_path() -> "str | None":
    """Locate config.example.yaml: at the repo root (one level above this
    package), falling back to the current directory. Independent of the caller's
    cwd so the scaffold works whether run from the repo or an operator's own dir."""
    here = os.path.dirname(os.path.abspath(__file__))
    for cand in (os.path.join(os.path.dirname(here), "config.example.yaml"),
                 os.path.join(os.getcwd(), "config.example.yaml")):
        if os.path.isfile(cand):
            return cand
    return None


def _starter_config_text(example: str) -> str:
    """Derive a starter config from the example text: identical content and
    comments, but with an EMPTY ``scope.cidrs``.

    The point is safety. A verbatim copy would carry the example's sample range
    (10.0.10.0/24), so a blind re-run would actively scan a network the operator
    never chose. Emptying the scope makes a blind re-run hit the existing
    authorization guard (empty cidrs -> refuse) instead. The operator must type
    their authorized range in by hand -- exactly the intended friction.
    """
    out: list[str] = []
    lines = example.splitlines()
    i, replaced = 0, False
    while i < len(lines):
        line = lines[i]
        if not replaced and line.strip().startswith("cidrs:"):
            indent = line[: len(line) - len(line.lstrip())]
            out.append(f"{indent}cidrs: []   # SET THIS to your AUTHORIZED range(s), "
                       f"e.g. [10.0.10.0/24]. Empty => refused (authorization guard).")
            # Drop the sample list items that belonged to this key (the
            # more-indented "- ..." lines immediately following it).
            item_floor = len(indent)
            i += 1
            while i < len(lines) and lines[i].strip().startswith("-") \
                    and (len(lines[i]) - len(lines[i].lstrip())) > item_floor:
                i += 1
            replaced = True
            continue
        out.append(line)
        i += 1
    banner = (
        "# ---------------------------------------------------------------------------\n"
        "# Starter config scaffolded by `grc-run` from config.example.yaml.\n"
        "# EDIT scope.cidrs below to the network range you are AUTHORIZED to scan,\n"
        "# then re-run. The tool refuses to run with an empty scope, by design.\n"
        "# ---------------------------------------------------------------------------\n"
    )
    return banner + "\n".join(out) + "\n"


def _scaffold_config(dest: str) -> int:
    """Write a starter config to ``dest`` and exit asking for an authorized
    scope. Returns exit code 2 either way (nothing ran) -- so a scheduled job
    that finds no config stops cleanly instead of scanning a template scope."""
    example = _example_config_path()
    if example is None:
        print(f"config error: {dest} not found, and no config.example.yaml was "
              f"available to scaffold one from. Create {dest} with an authorized "
              f"scope first.", file=sys.stderr)
        return 2
    try:
        parent = os.path.dirname(dest)
        if parent:
            os.makedirs(parent, exist_ok=True)
        with open(example, "r", encoding="utf-8") as fh:
            starter = _starter_config_text(fh.read())
        with open(dest, "w", encoding="utf-8") as fh:
            fh.write(starter)
    except OSError as exc:
        print(f"config error: could not scaffold {dest} from {example}: {exc}",
              file=sys.stderr)
        return 2
    print(f"No config found -- wrote a starter to {dest} (from "
          f"{os.path.basename(example)}).")
    print(f"  Next: set scope.cidrs in {dest} to the range you are AUTHORIZED to "
          f"scan, then re-run.")
    print("  It stays empty until you do, and an empty scope is refused -- the "
          "authorization guard, on purpose.")
    return 2


def cmd_run(args) -> int:
    if not os.path.exists(args.config):
        return _scaffold_config(args.config)
    try:
        cfg = load_config(args.config)
        cfg = apply_overrides(
            cfg, cidrs=args.cidr, exclude=args.exclude, output_dir=args.output,
            cis_level=args.cis_level, ssh_concurrency=args.concurrency,
            low_confidence_threshold=args.low_confidence_threshold,
            os_detect=args.os_detect, deep=args.deep,
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
    if args.deep:
        log.info("HIGH-ASSURANCE mode (--deep): CIS Level 2, oscap "
                 "--fetch-remote-resources, aggressive discovery (-T4 + OS detect) "
                 "-- maximum coverage; the target reaches out to the network")

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
        hosts = discovery.discover(cfg.scope, want_os=cfg.os_detect)
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
                              low_confidence_threshold=cfg.low_confidence_threshold,
                              dry_run=args.dry_run)
    finally:
        store.close()

    _print_summary(run, paths, dry_run=args.dry_run)
    return _exit_code_for_run(run, dry_run=args.dry_run)


# Exit code reserved for a run that completed but scanned zero hosts. 0, 1,
# and 2 are already spoken for elsewhere in this module (success; discovery/
# rmf failure; config scaffold-or-refusal), and ELI-143 already flags 2 as
# overloaded -- so this signal gets its own unused code rather than
# overloading a taken one further.
EXIT_ZERO_SCANNED = 3


def _exit_code_for_run(run: RunRecord, *, dry_run: bool = False) -> int:
    """The single home for the run's exit code, so the console summary, the
    report banner, and the process exit status all read the same
    `zero_scanned` predicate and can't disagree with each other."""
    return EXIT_ZERO_SCANNED if run.zero_scanned(dry_run=dry_run) else 0


def _print_summary(run: RunRecord, paths: dict, *, dry_run: bool = False) -> None:
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
    if run.zero_scanned(dry_run=dry_run):
        print()
        print("  *** ZERO HOSTS SCANNED -- this report has no findings. ***")
        if not run.hosts:
            print("      No hosts were discovered in this run's scope. See the "
                  "banner at the top of the report for detail.")
        else:
            print("      No host reached `scanned` this run -- see the coverage "
                  "gaps above and the banner at the top of the report for why.")


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


def cmd_rmf(args) -> int:
    from . import rmf
    paths: list[str] = []
    for p in args.arf:
        if os.path.isdir(p):
            for dirpath, _dirs, files in os.walk(p):
                if "arf.xml" in files:
                    paths.append(os.path.join(dirpath, "arf.xml"))
        elif os.path.isfile(p):
            paths.append(p)
        else:
            print(f"rmf: not found: {p}", file=sys.stderr)
            return 2
    if not paths:
        print("rmf: no arf.xml found in the given path(s)", file=sys.stderr)
        return 2
    run_dirs = {os.path.dirname(os.path.dirname(p)) for p in paths}
    if len(run_dirs) > 1:
        print(f"rmf: note: merging {len(paths)} ARF file(s) across {len(run_dirs)} "
              f"directories into one rollup; pass a single run directory for a "
              f"per-run view.", file=sys.stderr)

    try:
        rows = rmf.rollup_from_arf(paths)
    except rmf.RmfError as exc:
        print(f"rmf error: {exc}", file=sys.stderr)
        return 1

    if not rows:
        print(f"rmf: no 800-53 control mappings found in {len(paths)} ARF file(s) -- is "
              f"this SSG content with 800-53 references? Nothing written.",
              file=sys.stderr)
        return 1

    out = args.output or "control-rollup.csv"
    rmf.write_rollup_csv(rows, out)
    revs = rmf.summarize_revisions(rows)
    impl = sum(1 for r in rows if r.status == "Implemented")
    planned = sum(1 for r in rows if r.status == "Planned")
    print(f"800-53 control rollup from {len(paths)} ARF file(s): {len(rows)} controls "
          f"({impl} Implemented, {planned} Planned)")
    print(f"  wrote {out}")
    print(f"  refs are NIST 800-53 {revs} (from the SSG datastream); a DoD SSP baseline is "
          f"Rev 5 -- most map 1:1, confirm each.")
    print("  status is a suggestion from automated CIS checks, not an ATO decision.")
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
    r.add_argument("-c", "--config", default="config.yaml",
                   help="path to YAML config (default: ./config.yaml)")
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
    r.add_argument("--deep", action="store_true",
                   help="high-assurance mode: force CIS Level 2, oscap "
                        "--fetch-remote-resources, and aggressive discovery "
                        "(-T4 + OS detect) for maximum coverage. Aggressive: the "
                        "target reaches out to the network. Changes config_hash.")
    r.add_argument("--dry-run", action="store_true",
                   help="discover + classify only; no SSH, no scanning")
    r.add_argument("-v", "--verbose", action="store_true")
    r.set_defaults(func=cmd_run)

    h = sub.add_parser("history", help="list prior runs")
    h.add_argument("-o", "--output", default="./grc-output",
                   help="output directory holding history.db")
    h.set_defaults(func=cmd_history)

    rmf_p = sub.add_parser(
        "rmf", help="export a NIST 800-53 control rollup (SSP evidence) from ARF")
    rmf_p.add_argument("arf", nargs="+",
                       help="arf.xml file(s), or a run/host directory to search for arf.xml")
    rmf_p.add_argument("-o", "--output", help="output CSV (default: control-rollup.csv)")
    rmf_p.set_defaults(func=cmd_rmf)

    return p


def main(argv=None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
