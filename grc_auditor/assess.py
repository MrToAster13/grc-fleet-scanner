"""Per-host assessment: reach, detect and scan one host, then record its verdict.

``assess_host`` is the only code after triage (classify.py) that writes
``host.status`` and ``host.detail``, and it does so through one function,
``_record``. detect returns a ScanPlan or a Verdict, scan_host returns a
ScanResult or raises ScanFailed, and ``scan_verdict`` decides whether a parsed
scan certifies as SCANNED. See docs/adr/0002-one-writer-per-host-verdict.md.
"""

from __future__ import annotations

from typing import Callable, ContextManager

from .config import Config
from .detect import detect
from .logging_setup import get_logger
from .models import (
    HARD_CONFIDENCE_FLOOR, HostRecord, HostStatus, ScanResult, Verdict,
)
from .remote import (
    HostKeyMismatch, RemoteError, RemoteHost, RemoteHostProtocol,
)
from .scan import ScanFailed, scan_host

# connect(ip, credential_group, known_hosts) returns a context manager that
# yields a connected RemoteHostProtocol. RemoteHost in production; tests pass a
# factory that returns a fake.
ConnectFn = Callable[..., ContextManager[RemoteHostProtocol]]


def scan_verdict(scan: ScanResult,
                 hard_floor: float = HARD_CONFIDENCE_FLOOR) -> Verdict:
    """The single chokepoint deciding whether a parsed scan is trustworthy enough
    to record as SCANNED -- the structural enforcement of the never-false-pass
    directive. The caller always attaches the evidence; only the *status* is
    gated:

      * a scan that evaluated NOTHING (``total_outcomes == 0``) -- e.g. an empty
        or rule-result-less results.xml that ``parse_xccdf_results`` returns as
        all-zeros without raising -- becomes SCAN_ERROR, never a clean SCANNED.
      * a scan whose ``assessment_confidence`` falls below the NON-overridable
        ``hard_floor`` (independent of the operator-tunable low-confidence badge)
        becomes SCAN_ERROR: too little of the benchmark ran to certify a verdict.

    Anything that clears both bars is SCANNED, with no detail of its own.
    """
    if not scan.total_outcomes:
        return Verdict(
            HostStatus.SCAN_ERROR,
            "oscap produced results.xml with no rule outcomes to assess",
        )
    conf = scan.assessment_confidence
    if conf is None:
        # Outcomes existed but none owed a verdict (every selected check was
        # error/not-checked, or the profile selected nothing) -- nothing to
        # certify. Never a clean SCANNED.
        return Verdict(
            HostStatus.SCAN_ERROR,
            "assessment produced no scorable verdict -- evidence retained but not "
            "certifiable; check the scan account's sudo/privilege and the profile",
        )
    if conf < hard_floor:
        return Verdict(
            HostStatus.SCAN_ERROR,
            f"assessment incomplete: only {conf:.0f}% of the selected benchmark "
            f"produced a verdict (below the {hard_floor:.0f}% hard floor) -- evidence "
            f"retained but not certifiable; check the scan account's sudo/privilege",
        )
    return Verdict(HostStatus.SCANNED, None)


def _record(host: HostRecord, verdict: Verdict) -> None:
    """The one writer of host.status and host.detail after triage.

    A SCANNED verdict with no detail leaves the host's existing detail alone
    (detect's ready line when it had one, else the triage reason).
    """
    host.status = verdict.status
    if verdict.status is HostStatus.SCANNED and verdict.detail is None:
        return
    host.detail = verdict.detail


def assess_host(host: HostRecord, cfg: Config, run_id: str,
                artifacts_root: str,
                connect: ConnectFn = RemoteHost) -> HostRecord:
    """Reach, detect and scan one host. Never raises; the outcome is in
    host.status and host.detail.

    ``connect(ip, credential_group, known_hosts)`` opens the SSH session. It
    defaults to RemoteHost; tests pass a factory that returns a fake host.
    """
    log = get_logger()
    group = cfg.credential_group_for(host.ip)
    if group is None:  # defensive; classify should have caught this
        _record(host, Verdict(HostStatus.NO_CREDENTIALS,
                              "no credential group matched"))
        return host

    try:
        with connect(host.ip, group, cfg.known_hosts) as conn:
            plan = detect(host, conn, cfg)
            if isinstance(plan, Verdict):
                _record(host, plan)  # detect explained why it cannot scan
                return host
            try:
                scan = scan_host(host, conn, plan, run_id, artifacts_root,
                                 timeout=cfg.scope.host_timeout_seconds)
            except ScanFailed as exc:
                _record(host, Verdict(HostStatus.SCAN_ERROR, exc.detail))
                log.warning("scan[%s] failed: %s", host.ip, exc)
            except Exception as exc:
                # A known failure followed by a second error (for example the
                # temp-dir cleanup in scan_host's finally) keeps the known
                # failure's detail, which is the one the operator can act on.
                ctx = exc.__context__
                if isinstance(ctx, ScanFailed):
                    detail = ctx.detail
                else:
                    detail = f"scan failed: {exc}"
                _record(host, Verdict(HostStatus.SCAN_ERROR, detail))
                log.warning("scan[%s] failed: %s", host.ip, exc)
            else:
                # Chokepoint: a successful oscap exit + a parseable file is NOT
                # enough to certify SCANNED -- a zero-outcome or sub-floor scan is
                # recorded as a gap (SCAN_ERROR), never a clean pass. The evidence
                # stays attached either way.
                host.scan = scan
                verdict = scan_verdict(scan)
                if verdict.status is HostStatus.SCANNED:
                    verdict = Verdict(HostStatus.SCANNED, plan.ready_detail)
                _record(host, verdict)
                log.info("scan[%s]: %d pass / %d fail (score %s) -> %s",
                         host.ip, scan.passed, scan.failed,
                         f"{scan.score:.1f}" if scan.score is not None else "n/a",
                         host.status.value)
    except HostKeyMismatch as exc:
        # Distinct from plain unreachability: the host key no longer matches the
        # pinned key. Surfaced as a security finding (possible MITM / unverified
        # re-provisioning), not a coverage gap to shrug off.
        _record(host, Verdict(HostStatus.HOST_KEY_MISMATCH, str(exc)))
        log.warning("reach[%s] HOST KEY MISMATCH: %s", host.ip, exc)
    except RemoteError as exc:
        _record(host, Verdict(HostStatus.UNREACHABLE, str(exc)))
        log.warning("reach[%s] failed: %s", host.ip, exc)
    except Exception as exc:
        _record(host, Verdict(HostStatus.SCAN_ERROR, f"unexpected error: {exc}"))
        log.exception("host[%s] unexpected error", host.ip)
    return host
