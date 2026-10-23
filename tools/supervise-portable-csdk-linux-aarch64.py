#!/usr/bin/env python3
"""Internal Linux/AArch64 portable C-SDK candidate workflow driver.

The outer mode uses the existing ci_cargo.Supervisor to observe the complete
inner producer process tree and adds its own measured RSS to that peak. The
inner mode verifies the pinned LLVM input, records native host tools, and
invokes the existing C-SDK producer.
"""
from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import platform
import resource
import signal
import shutil
import stat
import subprocess
import sys
import time


MAX_RSS_BYTES = 4 * 1024**3
OBSERVER_RSS_RESERVE_BYTES = 256 * 1024**2
CHILD_RSS_LIMIT_BYTES = MAX_RSS_BYTES - OBSERVER_RSS_RESERVE_BYTES
MAX_WORK_BYTES = 12 * 1024**3
MAX_LOG_BYTES = 16 * 1024**2
MAX_PHASE_SECONDS = 1200
CAMPAIGN_SECONDS = 5400
REVIEW_RESERVE_SECONDS = 300
FINALIZATION_DEADLINE_SECONDS = CAMPAIGN_SECONDS - REVIEW_RESERVE_SECONDS
PRODUCER_WINDOW_SECONDS = 4400
INNER_PRODUCER_WORK_SECONDS = 4250
INNER_PRODUCER_CLEANUP_RESERVE_SECONDS = 150
OUTER_PRODUCER_DEADLINE_SECONDS = 4340
OUTER_CLEANUP_RESERVE_SECONDS = 60
PRODUCER_SHUTDOWN_GRACE_SECONDS = 15
# The parent Supervisor's 15s stop grace starts before this wrapper's handler
# runs. Keep one absolute 10s receipt deadline from handler entry, with an 8s
# operation cutoff and a 2s log-hash/atomic-write reserve. Each child wait and
# process-table call is clipped to the remaining operation budget.
OUTER_SIGNAL_RECEIPT_DEADLINE_SECONDS = 10.0
OUTER_SIGNAL_OPERATION_DEADLINE_SECONDS = 8.0
OUTER_SIGNAL_FINALIZATION_RESERVE_SECONDS = 2.0
OUTER_SIGNAL_PRODUCER_SETTLE_SECONDS = 1.5
OUTER_SIGNAL_OBSERVER_TIMEOUT_SECONDS = 1.5
OUTER_SIGNAL_CHILD_REAP_WAIT_SECONDS = 1.0
OUTER_SIGNAL_CHILD_REAP_AFTER_KILL_SECONDS = 0.5
OUTER_SIGNAL_FINAL_RECEIPT_WRITE_GUARD_SECONDS = 0.5
PROCESS_ROWS_TIMEOUT_SECONDS = 2.0
# Inner cleanup covers the producer TERM grace, both observed-group TERM/KILL
# grace periods, ten bounded ps waits, and the producer's 1s+3s direct reap.
INNER_CLEANUP_MINIMUM_SECONDS = (
    3 * PRODUCER_SHUTDOWN_GRACE_SECONDS + 10 * PROCESS_ROWS_TIMEOUT_SECONDS + 4)
# The outer reservation covers the parent's unchanged stop grace, the nested
# receipt deadline plus up to one process-table timeout of handler dispatch,
# and 15s of workflow scheduling/finalization slack.
OUTER_WORKFLOW_FINALIZATION_SLACK_SECONDS = 15
OUTER_CLEANUP_MINIMUM_SECONDS = (
    PRODUCER_SHUTDOWN_GRACE_SECONDS + OUTER_SIGNAL_RECEIPT_DEADLINE_SECONDS
    + PROCESS_ROWS_TIMEOUT_SECONDS + OUTER_WORKFLOW_FINALIZATION_SLACK_SECONDS)
ARTIFACT_PAYLOAD_BYTES = 127 * 1024**2
ARTIFACT_BYTES = 128 * 1024**2
WORKFLOW_SCHEMA = "ami-rust-portable-csdk-linux-aarch64-supervision-v1"
INNER_SCHEMA = "ami-rust-portable-csdk-linux-aarch64-producer-v1"
CLAIM = "C-SDK candidate prerequisite only; not Rust, SDK, L1, RC4, or release qualification"

EXPECTED = {
    "release/ci_cargo.py": "3f431b9fbb2352890fbcbdbdd8bf6102b1d12cb076507cf6eb298a9e27e23d70",
    "release/ci-resources.json": "b9a5fbfff842847c30b5f56ea4e1d3a368f4bda30689f0407ed9d33610571646",
    "release/ci-artifact-policy.json": "c8399c601d6209fa6b34811ace06a355f3a177e31c1dad883f33eec749024e4e",
    "release/ci_sdk.py": "378a940646368de4369076eb5daae789c0864869fcfb3b30bf05022ab1b804f2",
    "release/prepare_sdk.py": "57e447ca6dad3b013c0aa3f692e09246c8e9330de7d1d168be8ffa3247924a43",
    "release/ci_csdk.py": "44245c9645a53c73124787d6ead4e95014d029a4744b9162dbab2fce2f57819b",
    "release/csdk_producer.py": "b21ac90ba5e9e76cf6b49a69201378209adc25c641bdf9584132de43cd0acce6",
    "release/test_csdk_supervision.py": "ded55566c44587f401284e6077a9a01fd033703edab18b00c6b724e0815cb91e",
    "release/csdk_archive.py": "9c20f9e1f6f45f3baf4c044c5511860c46b7ee73c8f8fd1cbbebd1dce2991d15",
    "release/csdk_metadata.py": "efbdaff73fae189a1aa59d3b9dfa5a217e9d7696db6d7e3389514adad1e6d53b",
    "release/csdk_nouveau.py": "96de187a1090a9211d35a615b5245c48253ec490eed55adbe0a128c9cabefd58",
    "release/csdk_recipes.py": "84f4c598ac4b3d50c9ea8f61a323afa8e84b5fd4fd2c941a909cee0497e3e779",
    "release/ci-sdk-inputs.json": "70ea2900ba0e61213c6636fe1ee1c9bb0666e975847aee5ee5dc52797b437162",
    "release/portable-csdk/spec.json": "1b6f413082dc2ee087d91bc9838850a9f42f7f4a28829bfcb88d60ed1dacfdb3",
    "release/portable-csdk/toolchains/linux-aarch64.json": "be3dc1a696882367f4ff39ad393bf3ae66d6ee25fd73f8042eccfcb738defd68",
    "release/portable-csdk/original-profile.json": "79ac09e3b2237ea432bdc2a0e3b1cb0d91d36a37b6e53ce0d5c710a1cbd7b71e",
    "release/portable-csdk/profile.json": "e876263d5a322a3f7b4cb4ba203666352ec09d9f35f185b51a4d1f3fed06f337",
    "release/inputs/csdk.tar.xz": "70cc3e45969c6e1eca7e4c5c2183429b88424f6c22c8ec6bb90e6cc70452ab87",
    "release/inputs/portable-csdk.tar.xz": "942417c7b82218f5704eba168922fc348dc0ce5c17a236139c3353775209b99b",
    "release/csdk-source/csdk-corresponding-source.tar.xz": "7e62e28fb025e31aacdd3b6a6d14cef7d76703eb59dbaca02f2e2b4de68c6914",
    "release/csdk-source/manifest.json": "4e616c8373ac1dc36e5a109953b13e971783abcff0358f24eb49d78f606ad689",
    "release/patches/portable-csdk/series.json": "2ba73be8a78d79b471f7fafde9a43c6310a1a58efd18818e9e3d97ed7206c607",
}

LLVM_ARCHIVE = {
    "name": "aros-toolchain-v1-llvm11.0.0-linux-aarch64-pc-x86_64.tar.xz",
    "url": "https://github.com/metaneutrons/aros-toolchains/releases/download/v0.1.4/aros-toolchain-v1-llvm11.0.0-linux-aarch64-pc-x86_64.tar.xz",
    "bytes": 35097912,
    "sha256": "8d9be3b71eb02f60177c77ed62931caf4ebedd9c34b6ca9312b57157685c572e",
    "archive_root": "toolchain",
    "expanded_bytes": 192872017,
    "regular_files": 2754,
    "symlinks": 134,
    "tar_members": 3051,
    "clang": {
        "path": "bin/clang-11",
        "bytes": 133112,
        "sha256": "9fe7d123cee50d1c04017a934ca547ef488c399decf5b656d931b8dd2133daea",
        "version_prefix": "clang version 11.0.0",
    },
}

CANDIDATE = {
    "archive_name": "csdk-component.tar.xz",
    "archive_bytes": 5619304,
    "archive_sha256": "942417c7b82218f5704eba168922fc348dc0ce5c17a236139c3353775209b99b",
    "profile_name": "csdk-profile.json",
    "profile_bytes": 467692,
    "profile_sha256": "e876263d5a322a3f7b4cb4ba203666352ec09d9f35f185b51a4d1f3fed06f337",
}

NATIVE_TOOL_SEARCH_PATH = "/usr/local/bin:/usr/bin:/bin"
NATIVE_TOOL_RUNTIME_PATH = NATIVE_TOOL_SEARCH_PATH + ":/usr/sbin:/sbin"

NATIVE_TOOLS = {
    "cc": ("cc", ["--version"]),
    "cmake": ("cmake", ["--version"]),
    "pkg-config": ("pkg-config", ["--version"]),
    "perl": ("perl", ["-v"]),
    "git": ("git", ["--version"]),
    "patch": ("/usr/bin/patch", ["--version"]),
}

OUTER_FAILURE_CONTEXT: dict = {}


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def file_identity(path: Path) -> dict:
    if path.is_symlink() or not path.is_file():
        raise ValueError("expected a regular file: " + str(path))
    return {"path": str(path), "bytes": path.stat().st_size, "sha256": sha256(path)}


def write_json(path: Path, record: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("xb") as stream:
        stream.write((json.dumps(record, sort_keys=True, indent=2) + "\n").encode())


def write_json_fresh_atomic(path: Path, record: dict) -> None:
    temporary = path.with_name(path.name + ".provisional")
    if path.exists() or path.is_symlink() or temporary.exists() or temporary.is_symlink():
        raise ValueError("fresh provisional receipt path required")
    try:
        with temporary.open("xb") as stream:
            stream.write((json.dumps(record, sort_keys=True, indent=2) + "\n").encode())
        os.link(temporary, path, follow_symlinks=False)
    finally:
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass


def replace_json(path: Path, record: dict) -> None:
    temporary = path.with_name(path.name + ".finalizing")
    if temporary.exists() or temporary.is_symlink():
        raise ValueError("fresh atomic receipt temporary required")
    with temporary.open("xb") as stream:
        stream.write((json.dumps(record, sort_keys=True, indent=2) + "\n").encode())
    os.replace(temporary, path)


def replace_json_before_deadline(path: Path, record: dict, *, deadline: float) -> tuple[bool, bool]:
    """Promote a final receipt only if its bounded write leaves a rename margin."""
    temporary = path.with_name(path.name + ".finalizing")
    if temporary.exists() or temporary.is_symlink():
        raise ValueError("fresh atomic receipt temporary required")
    with temporary.open("xb") as stream:
        stream.write((json.dumps(record, sort_keys=True, indent=2) + "\n").encode())
    if time.monotonic() + OUTER_SIGNAL_FINAL_RECEIPT_WRITE_GUARD_SECONDS >= deadline:
        temporary.unlink()
        return False, False
    os.replace(temporary, path)
    return time.monotonic() < deadline, True


def _bounded_timeout(deadline: float, maximum: float, *, reserve: float = 0.0) -> float:
    return max(0.0, min(maximum, deadline - time.monotonic() - reserve))


def _outer_signal_cleanup(process, seen_groups, ci_cargo_module, *, received_at: float,
                          signal_group=None, get_session_id=None) -> dict:
    """Finish nested cleanup inside one deadline shorter than the outer 15s grace."""
    deadline = received_at + OUTER_SIGNAL_OPERATION_DEADLINE_SECONDS
    if signal_group is None:
        signal_group = os.killpg
    if get_session_id is None:
        get_session_id = os.getsid
    result = {
        "group_ids": sorted(seen_groups), "sigterm_group_ids": [], "sigkill_group_ids": [],
        "remaining_group_ids": sorted(seen_groups), "unsignaled_group_ids": [],
        "foreign_session_group_ids": [], "unverified_session_group_ids": [],
        "ambiguous_session_group_ids": [],
        "signal_census_complete": False, "signal_deadline_exhausted": False,
        "observer_errors": [],
        "signal_errors": [], "complete": False, "incomplete_cleanup": True,
        "status": "incomplete_cleanup", "receipt_deadline_seconds":
            OUTER_SIGNAL_RECEIPT_DEADLINE_SECONDS,
        "operation_deadline_seconds": OUTER_SIGNAL_OPERATION_DEADLINE_SECONDS,
        "operation_cutoff_monotonic": deadline,
        "process_table_calls": 0,
    }
    if process is None:
        result["observer_errors"].append("RuntimeError: producer process was not started")
        result["direct_child_reap"] = {
            "schema": "ami-rust-direct-child-reap-v1", "status": "incomplete_cleanup",
            "incomplete_cleanup": True, "wait_attempt_count": 0,
            "sigkill_attempted": False, "return_code": None,
        }
        return result

    wrapper_session_id = None
    wrapper_session_error = None
    try:
        wrapper_session_id = get_session_id(0)
    except Exception as error:
        wrapper_session_error = type(error).__name__ + ": " + str(error)[:200]

    def classify_owned_groups(rows, fresh_descendants):
        """Classify current descendant groups and retained same-session orphans."""
        observed = set(seen_groups) & {row[2] for row in rows}
        owned = observed & set(fresh_descendants)
        foreign, unverified, ambiguous = [], [], []
        for group in sorted(observed - owned):
            sessions = set()
            errors = []
            for pid, _parent, row_group, _rss in rows:
                if row_group != group or pid <= 1:
                    continue
                try:
                    sessions.add(get_session_id(pid))
                except ProcessLookupError:
                    # The process exited after the bounded process-table read.
                    continue
                except Exception as error:
                    errors.append(type(error).__name__ + ": " + str(error)[:160])
            if wrapper_session_id is None or errors:
                unverified.append(group)
                detail = ("; ".join(errors) if errors else
                          "wrapper session is unavailable: " + str(wrapper_session_error))
                result["observer_errors"].append(
                    "session-census:" + str(group) + ": " + detail)
            elif wrapper_session_id in sessions:
                owned.add(group)
            elif sessions:
                foreign.append(group)
                ambiguous.append(group)
                result["observer_errors"].append(
                    "session-census:" + str(group)
                    + ": historical live PGID is in another session and ownership is ambiguous")
            # No sessions means all process rows raced away during getsid;
            # the final census will decide whether anything remains.
        result["foreign_session_group_ids"] = sorted(
            set(result["foreign_session_group_ids"]) | set(foreign))
        result["unverified_session_group_ids"] = sorted(
            set(result["unverified_session_group_ids"]) | set(unverified))
        result["ambiguous_session_group_ids"] = sorted(
            set(result["ambiguous_session_group_ids"]) | set(ambiguous))
        return sorted(owned), sorted(set(unverified) | set(ambiguous))

    # Give the producer's existing signal handler a short chance to write its
    # own failure receipt. The reserve below guarantees time for census, kill,
    # direct-child reap, a final census, and the wrapper receipt.
    wait_seconds = _bounded_timeout(
        deadline, OUTER_SIGNAL_PRODUCER_SETTLE_SECONDS,
        reserve=(OUTER_SIGNAL_OBSERVER_TIMEOUT_SECONDS
                 + OUTER_SIGNAL_CHILD_REAP_WAIT_SECONDS
                 + OUTER_SIGNAL_CHILD_REAP_AFTER_KILL_SECONDS
                 + OUTER_SIGNAL_OBSERVER_TIMEOUT_SECONDS))
    if process.poll() is None and wait_seconds > 0:
        try:
            process.wait(timeout=wait_seconds)
        except subprocess.TimeoutExpired:
            pass
        except BaseException as error:
            result["observer_errors"].append(
                "producer-settle:" + type(error).__name__ + ": " + str(error)[:200])

    rows = None
    initial_census_complete = False
    fresh_descendant_groups = None
    observer_timeout = _bounded_timeout(
        deadline, OUTER_SIGNAL_OBSERVER_TIMEOUT_SECONDS,
        reserve=(OUTER_SIGNAL_CHILD_REAP_WAIT_SECONDS
                 + OUTER_SIGNAL_CHILD_REAP_AFTER_KILL_SECONDS
                 + OUTER_SIGNAL_OBSERVER_TIMEOUT_SECONDS))
    if observer_timeout > 0:
        result["process_table_calls"] += 1
        try:
            rows = ci_cargo_module.process_rows(timeout=observer_timeout)
            fresh_descendant_groups = set(
                ci_cargo_module.descendant_process_groups(process.pid, rows))
            seen_groups.update(fresh_descendant_groups)
            result["group_ids"] = sorted(seen_groups)
            initial_census_complete = True
        except Exception as error:
            result["observer_errors"].append(
                "initial-census:" + type(error).__name__ + ": " + str(error)[:200])
    else:
        result["observer_errors"].append("initial-census:TimeoutError: operation budget exhausted")

    # Keep historical PGIDs because producer helpers can be reparented or
    # started in another session. Fresh descendants are attributable from the
    # current tree; a historical orphan is attributable only if its members
    # still resolve to this wrapper's session. A live foreign-session PGID is
    # ambiguous (it may be an owned helper or a reused unrelated PGID), so fail
    # closed without signaling it. Walk confirmed groups until the absolute
    # cutoff rather than imposing a fixed batch cap.
    if rows is not None and initial_census_complete and fresh_descendant_groups is not None:
        live_groups, unverified_groups = classify_owned_groups(rows, fresh_descendant_groups)
        result["signal_census_complete"] = True
        result["unsignaled_group_ids"].extend(unverified_groups)
        for index, group in enumerate(live_groups):
            if time.monotonic() >= deadline:
                result["signal_deadline_exhausted"] = True
                result["unsignaled_group_ids"].extend(live_groups[index:])
                result["signal_errors"].append(
                    "deadline:TimeoutError: operation cutoff reached before all live groups were signaled")
                break
            try:
                signal_group(group, signal.SIGKILL)
                result["sigkill_group_ids"].append(group)
            except ProcessLookupError:
                # The observed group exited between census and kill.
                pass
            except BaseException as error:
                result["unsignaled_group_ids"].append(group)
                result["signal_errors"].append(
                    "killpg:" + str(group) + ":" + type(error).__name__ + ": "
                    + str(error)[:200])
            if time.monotonic() >= deadline:
                result["signal_deadline_exhausted"] = True
                if index + 1 < len(live_groups):
                    result["unsignaled_group_ids"].extend(live_groups[index + 1:])
                result["signal_errors"].append(
                    "deadline:TimeoutError: operation cutoff reached during group signaling")
                break
    elif seen_groups:
        result["observer_errors"].append(
            "signal-census:RuntimeError: fresh descendant census did not complete; no groups signaled")

    reap_deadline = deadline - OUTER_SIGNAL_OBSERVER_TIMEOUT_SECONDS
    first_wait = _bounded_timeout(
        reap_deadline, OUTER_SIGNAL_CHILD_REAP_WAIT_SECONDS,
        reserve=OUTER_SIGNAL_CHILD_REAP_AFTER_KILL_SECONDS)
    second_wait = _bounded_timeout(
        reap_deadline, OUTER_SIGNAL_CHILD_REAP_AFTER_KILL_SECONDS)
    try:
        result["direct_child_reap"] = ci_cargo_module.reap_child_bounded(
            process, wait_seconds=first_wait, sigkill_wait_seconds=second_wait)
    except BaseException as error:
        result["direct_child_reap"] = {
            "schema": "ami-rust-direct-child-reap-v1", "status": "incomplete_cleanup",
            "incomplete_cleanup": True, "wait_attempt_count": 0,
            "sigkill_attempted": False, "return_code": process.returncode,
            "signal_errors": ["reap:" + type(error).__name__ + ": " + str(error)[:200]],
        }
        result["signal_errors"].extend(result["direct_child_reap"]["signal_errors"])

    final_rows = None
    final_descendant_groups = None
    final_owned_groups = None
    final_unverified_groups = None
    final_timeout = _bounded_timeout(
        deadline, OUTER_SIGNAL_OBSERVER_TIMEOUT_SECONDS)
    if final_timeout > 0:
        result["process_table_calls"] += 1
        try:
            final_rows = ci_cargo_module.process_rows(timeout=final_timeout)
            final_descendant_groups = set(
                ci_cargo_module.descendant_process_groups(process.pid, final_rows))
            seen_groups.update(final_descendant_groups)
            result["group_ids"] = sorted(seen_groups)
            final_owned_groups, final_unverified_groups = classify_owned_groups(
                final_rows, final_descendant_groups)
        except Exception as error:
            result["observer_errors"].append(
                "final-census:" + type(error).__name__ + ": " + str(error)[:200])
    else:
        result["observer_errors"].append("final-census:TimeoutError: operation budget exhausted")

    if final_rows is not None and final_descendant_groups is not None:
        # Include same-session groups that were reparented before the final
        # descendant walk. Unverified members remain a fail-closed remainder;
        # positively foreign PGID reuse is never reported as our live child.
        result["remaining_group_ids"] = sorted(
            set(final_owned_groups or ()) | set(final_unverified_groups or ()))
        not_attempted = (set(result["remaining_group_ids"])
                         - set(result["sigkill_group_ids"]))
        result["unsignaled_group_ids"] = sorted(
            set(result["unsignaled_group_ids"]) | not_attempted)
    else:
        result["remaining_group_ids"] = sorted(seen_groups)
    within_operation_deadline = time.monotonic() < deadline
    if not within_operation_deadline:
        result["observer_errors"].append(
            "operation-deadline:TimeoutError: outer signal operation cutoff was reached")
    child_complete = (result["direct_child_reap"].get("status") == "complete"
                      and process.returncode is not None)
    result["complete"] = bool(
        within_operation_deadline and rows is not None and initial_census_complete
        and final_rows is not None and child_complete
        and not result["remaining_group_ids"]
        and not result["unsignaled_group_ids"] and not result["signal_deadline_exhausted"]
        and not result["observer_errors"] and not result["signal_errors"])
    result["incomplete_cleanup"] = not result["complete"]
    result["status"] = "complete" if result["complete"] else "incomplete_cleanup"
    result["elapsed_seconds"] = round(time.monotonic() - received_at, 6)
    result["configured_outer_stop_grace_seconds"] = PRODUCER_SHUTDOWN_GRACE_SECONDS
    result["handler_dispatch_allowance_seconds"] = PROCESS_ROWS_TIMEOUT_SECONDS
    result["minimum_outer_escalation_margin_seconds"] = round(
        PRODUCER_SHUTDOWN_GRACE_SECONDS - PROCESS_ROWS_TIMEOUT_SECONDS
        - OUTER_SIGNAL_RECEIPT_DEADLINE_SECONDS, 6)
    return result


def receipt_file_identity(path: Path, *, deadline: float) -> dict:
    if path.is_symlink() or not path.is_file():
        raise ValueError("expected a regular receipt log: " + str(path))
    size = path.stat().st_size
    if size > MAX_LOG_BYTES:
        raise ValueError("receipt log exceeds the pinned aggregate log ceiling")
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        while True:
            if time.monotonic() >= deadline:
                raise TimeoutError("receipt log hashing exceeded its finalization reserve")
            block = stream.read(256 * 1024)
            if not block:
                break
            digest.update(block)
    return {"path": str(path), "bytes": size, "sha256": digest.hexdigest()}


class _SupervisorStopRequested(KeyboardInterrupt):
    pass


def run_child_with_deadline(command, *, cwd: Path, env: dict[str, str], stdout, stderr,
                            timeout: float, label: str, timeout_record: Path,
                            ci_cargo_module, shutdown_grace_seconds: float | None = None) -> int:
    """Stop a direct producer and every observed compiler process group on timeout."""
    if timeout <= 0 or timeout > INNER_PRODUCER_WORK_SECONDS:
        raise ValueError("producer timeout exceeds the inner work deadline")
    if timeout_record.exists() or timeout_record.is_symlink():
        raise ValueError("fresh producer timeout receipt required")
    grace = (PRODUCER_SHUTDOWN_GRACE_SECONDS if shutdown_grace_seconds is None
             else shutdown_grace_seconds)
    if grace < 0 or grace > PRODUCER_SHUTDOWN_GRACE_SECONDS:
        raise ValueError("producer cleanup grace exceeds the pinned shutdown bound")

    previous_sigterm = signal.getsignal(signal.SIGTERM)
    received_sigterm_count = 0
    outer_signal_received_at = None
    cleanup_attempts = 0
    cleanup_started = False

    def outer_stop(signum, _frame):
        nonlocal received_sigterm_count, cleanup_started, outer_signal_received_at
        received_sigterm_count += 1
        if not cleanup_started:
            cleanup_started = True
            outer_signal_received_at = time.monotonic()
            raise _SupervisorStopRequested(
                "outer supervisor sent SIGTERM " + str(signum))

    process = None
    seen_descendant_groups = set()
    primary_reason = None
    primary_error = None
    group_cleanup = None
    cleanup_error = None
    direct_child_sigkill_fallback = False
    try:
        signal.signal(signal.SIGTERM, outer_stop)
        # Deliberately inherit this wrapper's session/process group. The outer
        # Supervisor owns that group; this wrapper separately tracks compiler
        # process groups created by the producer below it.
        process = subprocess.Popen(command, cwd=cwd, env=env, stdout=stdout, stderr=stderr,
                                   start_new_session=False)
        deadline = time.monotonic() + timeout

        def observe_descendants(*, timeout=PROCESS_ROWS_TIMEOUT_SECONDS):
            rows = ci_cargo_module.process_rows(timeout=timeout)
            observed = set(ci_cargo_module.descendant_process_groups(process.pid, rows))
            seen_descendant_groups.update(observed)
            return rows

        try:
            while process.poll() is None:
                observe_descendants()
                if time.monotonic() >= deadline:
                    primary_reason = "producer_deadline"
                    cleanup_started = True
                    break
                time.sleep(0.05)
            if primary_reason is None and process.poll() is not None:
                rows = observe_descendants()
                if any(group in seen_descendant_groups
                       for _, _, group, _ in rows):
                    primary_reason = "producer_exited_with_descendant_process_groups"
                    cleanup_started = True
        except _SupervisorStopRequested as error:
            primary_reason = "outer_supervisor_sigterm"
            primary_error = error
            cleanup_started = True
        except BaseException as error:
            primary_reason = "producer_observer_or_wait_failure"
            primary_error = error
            cleanup_started = True

        if primary_reason is None:
            return process.returncode

        cleanup_attempts += 1
        outer_signal = primary_reason == "outer_supervisor_sigterm"
        cleanup_grace = (OUTER_SIGNAL_PRODUCER_SETTLE_SECONDS if outer_signal else grace)
        if outer_signal:
            signal_at = outer_signal_received_at or time.monotonic()
            provisional = {
                "schema": "ami-rust-portable-csdk-producer-timeout-v1",
                "status": "FAILED", "label": label, "timeout_seconds": timeout,
                "termination_reason": primary_reason, "termination_signal": "SIGTERM",
                "driver_sigterm_delivery_count": received_sigterm_count,
                "cleanup_attempts": cleanup_attempts,
                "sigterm_grace_seconds": cleanup_grace,
                "configured_sigterm_grace_seconds": grace,
                "candidate_accepted": False, "cleanup_status": "incomplete_cleanup",
                "cleanup_complete": False, "receipt_phase": "cleanup_in_progress",
                "outer_signal_cleanup_deadline_seconds": OUTER_SIGNAL_RECEIPT_DEADLINE_SECONDS,
                "outer_signal_operation_deadline_seconds": OUTER_SIGNAL_OPERATION_DEADLINE_SECONDS,
                "outer_signal_finalization_reserve_seconds": OUTER_SIGNAL_FINALIZATION_RESERVE_SECONDS,
                "primary_error": (type(primary_error).__name__ + ": " + str(primary_error)[:300]
                                  if primary_error else None),
            }
            provisional_error = None
            try:
                write_json_fresh_atomic(timeout_record, provisional)
            except BaseException as error:
                provisional_error = type(error).__name__ + ": " + str(error)[:300]

            try:
                if process.poll() is None:
                    process.send_signal(signal.SIGTERM)
            except ProcessLookupError:
                pass
            except BaseException as error:
                cleanup_error = type(error).__name__ + ": " + str(error)[:300]
                primary_error = primary_error or error

            bounded = _outer_signal_cleanup(
                process, seen_descendant_groups, ci_cargo_module, received_at=signal_at)
            direct_child_reap = bounded.pop("direct_child_reap")
            group_cleanup = bounded
            if provisional_error:
                cleanup_error = cleanup_error or ("provisional timeout receipt: " + provisional_error)
            group_cleanup["complete"] = bool(
                group_cleanup.get("complete") and direct_child_reap.get("status") == "complete"
                and cleanup_error is None and provisional_error is None)
            group_cleanup["incomplete_cleanup"] = not group_cleanup["complete"]
            group_cleanup["status"] = (
                "complete" if group_cleanup["complete"] else "incomplete_cleanup")
            direct_child_sigkill_fallback = direct_child_reap.get("sigkill_attempted", False)
            record = {
                **provisional,
                "receipt_phase": "final",
                "driver_sigterm_delivery_count": received_sigterm_count,
                "direct_child_sigkill_fallback": direct_child_sigkill_fallback,
                "direct_child_reap": direct_child_reap,
                "cleanup_error": cleanup_error,
                "descendant_process_group_cleanup": group_cleanup,
                "child_exit_code": process.returncode,
                "candidate_accepted": False,
                "cleanup_status": group_cleanup["status"],
                "cleanup_complete": bool(group_cleanup["complete"]),
            }
            final_deadline = signal_at + OUTER_SIGNAL_RECEIPT_DEADLINE_SECONDS
            log_hash_deadline = (final_deadline
                                 - OUTER_SIGNAL_FINAL_RECEIPT_WRITE_GUARD_SECONDS)
            receipt_errors = []
            receipt_paths = (("stdout", Path(stdout.name)), ("stderr", Path(stderr.name)))
            try:
                aggregate_log_bytes = sum(path.stat().st_size for _, path in receipt_paths)
                if aggregate_log_bytes > MAX_LOG_BYTES:
                    raise ValueError("receipt logs exceed the aggregate 16MiB ceiling")
            except BaseException as error:
                aggregate_log_bytes = None
                receipt_errors.append(
                    "aggregate-logs: " + type(error).__name__ + ": " + str(error)[:200])
            for key, path in receipt_paths:
                try:
                    if aggregate_log_bytes is None:
                        raise ValueError("aggregate log sizes were not verified")
                    record[key] = receipt_file_identity(path, deadline=log_hash_deadline)
                except BaseException as error:
                    receipt_errors.append(key + ": " + type(error).__name__ + ": " + str(error)[:200])
                    try:
                        stat = path.stat()
                        record[key] = {"path": str(path), "bytes": stat.st_size,
                                       "sha256": None, "identity_error": type(error).__name__}
                    except OSError:
                        record[key] = {"path": str(path), "bytes": None,
                                       "sha256": None, "identity_error": type(error).__name__}
            if receipt_errors:
                record["receipt_errors"] = receipt_errors
                record["cleanup_complete"] = False
                record["cleanup_status"] = "incomplete_cleanup"
                record["descendant_process_group_cleanup"]["complete"] = False
                record["descendant_process_group_cleanup"]["incomplete_cleanup"] = True
                record["descendant_process_group_cleanup"]["status"] = "incomplete_cleanup"
            record["outer_signal_elapsed_seconds"] = round(time.monotonic() - signal_at, 6)
            record["outer_signal_deadline_seconds"] = OUTER_SIGNAL_RECEIPT_DEADLINE_SECONDS
            record["outer_signal_handler_dispatch_allowance_seconds"] = PROCESS_ROWS_TIMEOUT_SECONDS
            record["minimum_outer_escalation_margin_seconds"] = round(
                PRODUCER_SHUTDOWN_GRACE_SECONDS - PROCESS_ROWS_TIMEOUT_SECONDS
                - OUTER_SIGNAL_RECEIPT_DEADLINE_SECONDS, 6)
            if time.monotonic() + OUTER_SIGNAL_FINAL_RECEIPT_WRITE_GUARD_SECONDS >= final_deadline:
                record["receipt_errors"] = sorted(set(record.get("receipt_errors", []) + [
                    "final receipt was not promoted because the deadline write margin was exhausted"
                ]))
                record["cleanup_complete"] = False
                record["cleanup_status"] = "incomplete_cleanup"
                record["descendant_process_group_cleanup"]["complete"] = False
                record["descendant_process_group_cleanup"]["incomplete_cleanup"] = True
                record["descendant_process_group_cleanup"]["status"] = "incomplete_cleanup"
                reason = primary_reason.replace("_", " ")
                raise TimeoutError(label + " failed: " + reason) from primary_error
            try:
                timely, promoted = replace_json_before_deadline(
                    timeout_record, record, deadline=final_deadline)
                if not timely:
                    record["receipt_errors"] = sorted(set(record.get("receipt_errors", []) + [
                        "final receipt promotion crossed its deadline; cleanup is incomplete"
                    ]))
                    record["cleanup_complete"] = False
                    record["cleanup_status"] = "incomplete_cleanup"
                    record["descendant_process_group_cleanup"]["complete"] = False
                    record["descendant_process_group_cleanup"]["incomplete_cleanup"] = True
                    record["descendant_process_group_cleanup"]["status"] = "incomplete_cleanup"
                    if promoted:
                        replace_json(timeout_record, record)
            except BaseException as error:
                cleanup_error = cleanup_error or (
                    "final timeout receipt: " + type(error).__name__ + ": " + str(error)[:200])
                primary_error = primary_error or error
            reason = primary_reason.replace("_", " ")
            raise TimeoutError(label + " failed: " + reason) from primary_error

        try:
            if process.poll() is None:
                process.send_signal(signal.SIGTERM)
        except ProcessLookupError:
            pass
        observer_errors = []
        grace_deadline = time.monotonic() + cleanup_grace
        while time.monotonic() < grace_deadline:
            try:
                observe_descendants()
            except (OSError, subprocess.SubprocessError, ValueError, TypeError) as error:
                message = type(error).__name__ + ": " + str(error)[:200]
                if message not in observer_errors:
                    observer_errors.append(message)
            child_alive = process.poll() is None
            groups_alive = bool(seen_descendant_groups)
            if seen_descendant_groups:
                try:
                    rows = ci_cargo_module.process_rows()
                    groups_alive = any(
                        group in seen_descendant_groups
                        for _, _, group, _ in rows)
                except (OSError, subprocess.SubprocessError, ValueError, TypeError) as error:
                    message = type(error).__name__ + ": " + str(error)[:200]
                    if message not in observer_errors:
                        observer_errors.append(message)
                    groups_alive = True
            if not child_alive and not groups_alive:
                break
            time.sleep(min(0.05, max(0.0, grace_deadline - time.monotonic())))

        try:
            observe_descendants()
        except (OSError, subprocess.SubprocessError, ValueError, TypeError) as error:
            message = type(error).__name__ + ": " + str(error)[:200]
            if message not in observer_errors:
                observer_errors.append(message)
        try:
            group_cleanup = ci_cargo_module.stop_process_groups(
                sorted(seen_descendant_groups),
                rows_reader=ci_cargo_module.process_rows,
                grace_seconds=cleanup_grace)
        except BaseException as error:
            # Keep the first deadline/observer failure, but retain a bounded
            # cleanup failure and still stop the direct producer below.
            cleanup_error = type(error).__name__ + ": " + str(error)[:300]
            primary_error = primary_error or error
            group_cleanup = {
                "group_ids": sorted(seen_descendant_groups),
                "sigterm_group_ids": [], "sigkill_group_ids": [],
                "remaining_group_ids": sorted(seen_descendant_groups),
                "observer_errors": [cleanup_error], "signal_errors": [],
                "complete": False, "incomplete_cleanup": True,
                "status": "incomplete_cleanup",
            }
            try:
                ci_cargo_module._signal_groups(
                    sorted(seen_descendant_groups), signal.SIGKILL)
            except BaseException:
                pass
        if observer_errors:
            group_cleanup["observer_errors"] = sorted(
                set(group_cleanup.get("observer_errors", [])) | set(observer_errors))
            group_cleanup["complete"] = False

        # The producer shares this wrapper's process group, so only signal the
        # direct child here; process-group cleanup above targets compiler groups.
        direct_child_reap = ci_cargo_module.reap_child_bounded(
            process, wait_seconds=min(1.0, max(0.1, cleanup_grace)), sigkill_wait_seconds=3.0)
        direct_child_sigkill_fallback = direct_child_reap["sigkill_attempted"]
        if direct_child_reap["status"] != "complete":
            cleanup_error = cleanup_error or "direct producer reaping remained incomplete"
            primary_error = primary_error or RuntimeError(cleanup_error)
            group_cleanup["observer_errors"] = sorted(set(
                group_cleanup.get("observer_errors", [])) | {cleanup_error})
            group_cleanup["complete"] = False
            group_cleanup["incomplete_cleanup"] = True
            group_cleanup["status"] = "incomplete_cleanup"
        group_cleanup["direct_child_reap"] = direct_child_reap
        group_cleanup["complete"] = bool(
            group_cleanup.get("complete")
            and direct_child_reap.get("status") == "complete"
            and process.returncode is not None)
        group_cleanup["incomplete_cleanup"] = not group_cleanup["complete"]
        group_cleanup["status"] = (
            "complete" if group_cleanup["complete"] else "incomplete_cleanup")

        record = {
            "schema": "ami-rust-portable-csdk-producer-timeout-v1",
            "status": "FAILED",
            "label": label,
            "timeout_seconds": timeout,
            "termination_reason": primary_reason,
            "termination_signal": "SIGTERM",
            "driver_sigterm_delivery_count": received_sigterm_count,
            "cleanup_attempts": cleanup_attempts,
            "sigterm_grace_seconds": cleanup_grace,
            "configured_sigterm_grace_seconds": grace,
            "direct_child_sigkill_fallback": direct_child_sigkill_fallback,
            "direct_child_reap": direct_child_reap,
            "cleanup_error": cleanup_error,
            "descendant_process_group_cleanup": group_cleanup,
            "child_exit_code": process.returncode,
            "stdout": file_identity(Path(stdout.name)),
            "stderr": file_identity(Path(stderr.name)),
            "candidate_accepted": False,
            "cleanup_status": "complete" if (
                group_cleanup.get("complete") and direct_child_reap.get("status") == "complete"
                and process.returncode is not None) else "incomplete_cleanup",
            "cleanup_complete": bool(group_cleanup.get("complete"))
                                and direct_child_reap.get("status") == "complete"
                                and process.returncode is not None,
            "primary_error": (type(primary_error).__name__ + ": " + str(primary_error)[:300]
                              if primary_error else None),
        }
        write_json(timeout_record, record)
        reason = primary_reason.replace("_", " ")
        raise TimeoutError(label + " failed: " + reason) from primary_error
    finally:
        signal.signal(signal.SIGTERM, previous_sigterm)


def read_json(path: Path, maximum: int = 64 * 1024**2) -> dict:
    if path.is_symlink() or not path.is_file() or path.stat().st_size > maximum:
        raise ValueError("missing, linked or oversized JSON: " + path.name)
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError("JSON root must be an object: " + path.name)
    return value


def load_module(path: Path, name: str):
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise ValueError("cannot load source module: " + str(path))
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    try:
        spec.loader.exec_module(module)
    except BaseException:
        sys.modules.pop(name, None)
        raise
    return module


def verify_pinned_sources(repo: Path) -> dict:
    rows = {}
    for relative, expected in EXPECTED.items():
        path = repo / relative
        actual = file_identity(path)
        if actual["sha256"] != expected:
            raise ValueError("source differs from frozen host-slice pin: " + relative)
        rows[relative] = actual
    return rows


def source_commit(repo: Path, expected: str) -> dict:
    if len(expected) != 40 or any(char not in "0123456789abcdef" for char in expected):
        raise ValueError("workflow source commit is missing or malformed")
    result = subprocess.run(["/usr/bin/git", "-C", str(repo), "rev-parse", "HEAD"],
                            check=True, capture_output=True, text=True, timeout=30)
    actual = result.stdout.strip()
    if actual != expected:
        raise ValueError("checked-out source commit differs from the workflow event SHA")
    status = subprocess.run(["/usr/bin/git", "-C", str(repo), "status", "--porcelain",
                             "--untracked-files=all"], check=True, capture_output=True,
                            text=True, timeout=30)
    if status.stdout:
        raise ValueError("protected source checkout is not clean")
    return {"head": actual, "clean": True}


def run_version(executable: Path, args: list[str], cwd: Path, env: dict[str, str]) -> dict:
    started = time.monotonic()
    result = subprocess.run([str(executable), *args], cwd=cwd, env=env,
                            capture_output=True, text=True, timeout=30, check=False)
    elapsed = time.monotonic() - started
    if result.returncode != 0 or elapsed > MAX_PHASE_SECONDS:
        raise ValueError("host tool identity command failed: " + executable.name)
    stdout, stderr = result.stdout[:8192], result.stderr[:8192]
    if len(result.stdout) > 8192 or len(result.stderr) > 8192:
        raise ValueError("host tool identity output exceeds its bound: " + executable.name)
    return {"argv": [str(executable), *args], "exit_code": result.returncode,
            "elapsed_seconds": round(elapsed, 3), "stdout": stdout, "stderr": stderr}


def tool_identity(name: str, command: str, args: list[str], cwd: Path,
                  env: dict[str, str]) -> tuple[Path, dict]:
    selected = command if command.startswith("/") else shutil.which(command, path=NATIVE_TOOL_SEARCH_PATH)
    if not selected:
        raise ValueError("required native host tool is unavailable: " + name)
    lexical = Path(selected)
    resolved = lexical.resolve(strict=True)
    if not resolved.is_file() or not os.access(resolved, os.X_OK):
        raise ValueError("native host tool is not an executable regular file: " + name)
    record = {"name": name, "selected_path": str(lexical),
              "resolved": file_identity(resolved),
              "version": run_version(resolved, args, cwd, env)}
    return resolved, record


def collect_native_host_tools(cwd: Path, env: dict[str, str]) -> tuple[dict, dict[str, Path]]:
    """Resolve and identify every host prerequisite before touching LLVM inputs."""
    tool_records, tool_paths = {}, {}
    for name, (command_name, args) in NATIVE_TOOLS.items():
        path, record = tool_identity(name, command_name, args, cwd, env)
        tool_paths[name] = path
        tool_records[name] = record
    cc_target = run_version(tool_paths["cc"], ["-dumpmachine"], cwd, env)
    if "aarch64" not in cc_target["stdout"].lower():
        raise ValueError("native C compiler does not target the runner's AArch64 host")
    tool_records["cc_target"] = cc_target
    if Path(NATIVE_TOOLS["patch"][0]).resolve(strict=True) != tool_paths["patch"]:
        raise ValueError("patch tool path differs from the producer's fixed /usr/bin/patch path")
    return tool_records, tool_paths


def verify_native_host_tools_unchanged(tool_records: dict) -> None:
    for name, record in tool_records.items():
        if name == "cc_target":
            continue
        resolved = Path(record["resolved"]["path"])
        if file_identity(resolved) != record["resolved"]:
            raise ValueError("native host tool changed during C-SDK production: " + name)


def redacted_error(error: BaseException, repo: Path, managed: Path) -> str:
    message = str(error).replace(str(repo), "<checkout>").replace(str(managed), "<managed>")
    return (type(error).__name__ + ": " + message.replace("\n", " "))[:2048]


def read_os_release() -> dict[str, str]:
    values = {}
    for line in Path("/etc/os-release").read_text().splitlines():
        if "=" in line:
            key, value = line.split("=", 1)
            values[key] = value.strip().strip('"')
    return values


def validate_nested_deadline_policy(
        process_rows_timeout: float = PROCESS_ROWS_TIMEOUT_SECONDS,
        supervisor_stop_grace_seconds: float = PRODUCER_SHUTDOWN_GRACE_SECONDS) -> None:
    if (INNER_PRODUCER_WORK_SECONDS + INNER_PRODUCER_CLEANUP_RESERVE_SECONDS
            != PRODUCER_WINDOW_SECONDS):
        raise ValueError("inner producer work and cleanup reserves do not meet the 4,400s boundary")
    if (OUTER_PRODUCER_DEADLINE_SECONDS + OUTER_CLEANUP_RESERVE_SECONDS
            != PRODUCER_WINDOW_SECONDS):
        raise ValueError("outer backup and cleanup reserves do not meet the 4,400s boundary")
    if process_rows_timeout != PROCESS_ROWS_TIMEOUT_SECONDS:
        raise ValueError("process observer timeout differs from the pinned cleanup calculation")
    if supervisor_stop_grace_seconds != PRODUCER_SHUTDOWN_GRACE_SECONDS:
        raise ValueError("shared supervisor grace differs from the pinned cleanup calculation")
    if (OUTER_SIGNAL_OPERATION_DEADLINE_SECONDS
            + OUTER_SIGNAL_FINALIZATION_RESERVE_SECONDS
            != OUTER_SIGNAL_RECEIPT_DEADLINE_SECONDS):
        raise ValueError("outer signal operation and receipt reserves do not meet the hard deadline")
    if OUTER_SIGNAL_OBSERVER_TIMEOUT_SECONDS > PROCESS_ROWS_TIMEOUT_SECONDS:
        raise ValueError("outer signal observer exceeds its bounded policy")
    if (OUTER_SIGNAL_PRODUCER_SETTLE_SECONDS
            + 2 * OUTER_SIGNAL_OBSERVER_TIMEOUT_SECONDS
            + OUTER_SIGNAL_CHILD_REAP_WAIT_SECONDS
            + OUTER_SIGNAL_CHILD_REAP_AFTER_KILL_SECONDS
            > OUTER_SIGNAL_OPERATION_DEADLINE_SECONDS):
        raise ValueError("outer signal waits and censuses exceed the operation cutoff")
    handler_dispatch_allowance = PROCESS_ROWS_TIMEOUT_SECONDS
    if (OUTER_SIGNAL_RECEIPT_DEADLINE_SECONDS + handler_dispatch_allowance
            > supervisor_stop_grace_seconds - 3):
        raise ValueError("outer signal receipt leaves less than three seconds before parent escalation")
    if (INNER_PRODUCER_WORK_SECONDS >= OUTER_PRODUCER_DEADLINE_SECONDS
            or OUTER_PRODUCER_DEADLINE_SECONDS - INNER_PRODUCER_WORK_SECONDS
            < INNER_CLEANUP_MINIMUM_SECONDS
            or INNER_PRODUCER_CLEANUP_RESERVE_SECONDS < INNER_CLEANUP_MINIMUM_SECONDS
            or OUTER_CLEANUP_RESERVE_SECONDS < OUTER_CLEANUP_MINIMUM_SECONDS):
        raise ValueError("nested deadlines leave insufficient ordered cleanup time")


def require_outer_runtime_directories(managed: Path) -> dict[str, Path]:
    """Validate the private HOME/TMP directories created once by outer_run."""
    if managed.is_symlink() or not managed.is_dir():
        raise ValueError("managed root must be a real directory")
    paths = {name: managed / name for name in ("home", "tmp")}
    for name, path in paths.items():
        try:
            info = path.lstat()
        except FileNotFoundError as error:
            raise ValueError("outer runtime directory is missing: " + name) from error
        if (not stat.S_ISDIR(info.st_mode) or info.st_uid != os.geteuid()
                or stat.S_IMODE(info.st_mode) != 0o700):
            raise ValueError("outer runtime directory is not a private owned directory: " + name)
    return paths


def create_outer_runtime_directories(managed: Path) -> dict[str, Path]:
    """Create HOME/TMP once in the outer process and return validated paths."""
    managed = managed.resolve(strict=True)
    if managed.is_symlink() or not managed.is_dir():
        raise ValueError("managed root must be a real directory")
    for name in ("home", "tmp"):
        path = managed / name
        path.mkdir(mode=0o700)
        path.chmod(0o700)
    return require_outer_runtime_directories(managed)


def inner_produce(repo: Path, managed: Path, artifact: Path, expected_head: str,
                  campaign_start: int) -> dict:
    validate_nested_deadline_policy()
    repo = repo.resolve(strict=True)
    managed = managed.resolve(strict=True)
    artifact = artifact.resolve(strict=True)
    runtime_dirs = require_outer_runtime_directories(managed)
    code_pins = verify_pinned_sources(repo)
    git_record = source_commit(repo, expected_head)
    policy_path = managed / "ci-artifact-policy.json"
    expected_policy_sha = os.environ.get("CSDK_POLICY_SHA256")
    if (not expected_policy_sha or sha256(policy_path) != expected_policy_sha
            or expected_policy_sha != EXPECTED["release/ci-artifact-policy.json"]):
        raise ValueError("pre-checkout artifact policy differs from the checked-out policy pin")

    ci_cargo = load_module(repo / "release/ci_cargo.py", "_portable_csdk_arm_ci_cargo")
    validate_nested_deadline_policy(
        ci_cargo.PROCESS_ROWS_TIMEOUT_SECONDS, ci_cargo.SUPERVISOR_STOP_GRACE_SECONDS)
    sdk = load_module(repo / "release/ci_sdk.py", "_portable_csdk_arm_ci_sdk")
    producer = load_module(repo / "release/csdk_producer.py", "_portable_csdk_arm_producer")
    resource_policy = read_json(repo / "release/ci-resources.json")
    capacity = sdk.validate_portable_csdk_resource_policy(resource_policy, managed)
    spec_path = repo / "release/portable-csdk/spec.json"
    spec = read_json(spec_path)
    if (spec.get("status") != "PINNED_CANDIDATE_THREE_HOST_QUALIFICATION_REQUIRED"
            or set(spec.get("toolchains", {})) != {"linux-aarch64", "linux-x86_64", "macos-aarch64"}):
        raise ValueError("C-SDK candidate source is not the reviewed three-host slice")
    host = sdk.portable_csdk_host_identity()
    if host != "linux-aarch64" or platform.machine().lower() not in {"aarch64", "arm64"}:
        raise ValueError("producer requires the native Ubuntu Linux/AArch64 host")
    if platform.system() != "Linux":
        raise ValueError("producer requires Linux")
    os_release = read_os_release()
    if os_release.get("ID") != "ubuntu" or os_release.get("VERSION_ID") != "24.04":
        raise ValueError("producer requires Ubuntu 24.04")

    spec_row = spec["toolchains"][host]
    archive_pin = spec_row.get("archive")
    profile_pin = spec_row.get("profile")
    expected_archive = {"kind": "tar", "url": LLVM_ARCHIVE["url"],
                        "bytes": LLVM_ARCHIVE["bytes"], "sha256": LLVM_ARCHIVE["sha256"],
                        "archive_root": LLVM_ARCHIVE["archive_root"]}
    expected_profile = {"path": "release/portable-csdk/toolchains/linux-aarch64.json",
                        "bytes": 488632,
                        "sha256": "be3dc1a696882367f4ff39ad393bf3ae66d6ee25fd73f8042eccfcb738defd68"}
    if archive_pin != expected_archive or profile_pin != expected_profile:
        raise ValueError("C-SDK ARM LLVM archive or profile differs from the frozen pin")
    loaded_spec, original_profile, candidate_profile = producer.load_inputs(spec_path)
    if loaded_spec != spec:
        raise ValueError("portable C-SDK producer loaded different inputs")
    input_paths = (
        "release/inputs/csdk.tar.xz",
        "release/inputs/portable-csdk.tar.xz",
        "release/portable-csdk/original-profile.json",
        "release/portable-csdk/profile.json",
        "release/csdk-source/csdk-corresponding-source.tar.xz",
        "release/csdk-source/manifest.json",
        "release/patches/portable-csdk/series.json",
    )
    input_identities = {relative: file_identity(repo / relative) for relative in input_paths}
    if (input_identities["release/inputs/portable-csdk.tar.xz"]["sha256"]
            != CANDIDATE["archive_sha256"]
            or len(original_profile.get("files", [])) != 2835
            or len(candidate_profile.get("files", [])) != 2835):
        raise ValueError("C-SDK source or baseline candidate profile differs from its frozen pin")

    # Check all six native host tools, including the compiler target, before
    # downloading or extracting the 35 MB LLVM archive. Use a small fixed
    # lookup path that includes the host-local installation prefix.
    native_env = {"HOME": str(runtime_dirs["home"]),
                  "TMPDIR": str(runtime_dirs["tmp"]), "TMP": str(runtime_dirs["tmp"]),
                  "TEMP": str(runtime_dirs["tmp"]), "PATH": NATIVE_TOOL_RUNTIME_PATH,
                  "LC_ALL": "C", "LANG": "C", "TZ": "UTC",
                  "PYTHONNOUSERSITE": "1", "PYTHONDONTWRITEBYTECODE": "1",
                  "GIT_TERMINAL_PROMPT": "0", "GIT_CONFIG_NOSYSTEM": "1",
                  "GIT_CONFIG_GLOBAL": os.devnull, "GIT_OPTIONAL_LOCKS": "0"}
    host_tool_start = time.monotonic()
    tool_records, tool_paths = collect_native_host_tools(managed, native_env)
    if time.monotonic() - host_tool_start > MAX_PHASE_SECONDS:
        raise TimeoutError("native host tool preflight exceeded 1200 seconds")

    input_root = managed / "inputs"
    archive_path = input_root / LLVM_ARCHIVE["name"]
    extract_path = managed / "arm-llvm-extracted"
    for path in (input_root, archive_path, extract_path, managed / "csdk-work",
                 managed / "csdk-output", managed / "tool-versions"):
        if path.exists() or path.is_symlink():
            raise ValueError("producer managed paths must be fresh: " + path.name)
    input_root.mkdir()
    stage_start = time.monotonic()
    download_record = ci_cargo.download_verified(
        archive_pin["url"], archive_pin["bytes"], archive_pin["sha256"], archive_path,
        expected_origin="github.com",
        redirect_hosts=("release-assets.githubusercontent.com", "objects.githubusercontent.com"),
        total_timeout=300)
    if time.monotonic() - stage_start > MAX_PHASE_SECONDS:
        raise TimeoutError("pinned LLVM download exceeded its 1200-second phase limit")
    if download_record != {"bytes": LLVM_ARCHIVE["bytes"], "sha256": LLVM_ARCHIVE["sha256"]}:
        raise ValueError("downloaded ARM LLVM archive receipt differs")

    stage_start = time.monotonic()
    current_bytes = (ci_cargo.directory_bytes(repo) + ci_cargo.directory_bytes(managed)
                     + ci_cargo.directory_bytes(artifact.parent))
    extraction = ci_cargo.safe_extract_tar(
        archive_path, extract_path, expanded_limit=256 * 1024**2,
        current_managed_bytes=current_bytes, overall_limit=MAX_WORK_BYTES)
    if (extraction.get("component_root") != LLVM_ARCHIVE["archive_root"]
            or extraction.get("member_count") != LLVM_ARCHIVE["tar_members"]
            or extraction.get("expanded_bytes") != LLVM_ARCHIVE["expanded_bytes"]):
        raise ValueError("ARM LLVM archive member or expansion totals differ")
    toolchain = extract_path / LLVM_ARCHIVE["archive_root"]
    profile = read_json(repo / profile_pin["path"], 2 * 1024**2)
    profile_receipt = sdk.verify_component(toolchain, profile, "portable C-SDK ARM LLVM")
    compiler = producer.pinned_file(spec_row["compiler"], root=toolchain)
    clang_identity = file_identity(compiler)
    if (clang_identity["bytes"] != LLVM_ARCHIVE["clang"]["bytes"]
            or clang_identity["sha256"] != LLVM_ARCHIVE["clang"]["sha256"]):
        raise ValueError("extracted ARM clang bytes differ from the independently reviewed pin")
    if time.monotonic() - stage_start > MAX_PHASE_SECONDS:
        raise TimeoutError("ARM LLVM extraction/profile phase exceeded 1200 seconds")

    env = dict(native_env)
    env["PATH"] = str(toolchain / "bin") + ":" + NATIVE_TOOL_RUNTIME_PATH
    clang_version = run_version(compiler, ["--version"], managed, env)
    if LLVM_ARCHIVE["clang"]["version_prefix"] not in clang_version["stdout"]:
        raise ValueError("ARM LLVM runtime version does not identify the pinned clang 11 release")

    if int(time.time()) - campaign_start >= PRODUCER_WINDOW_SECONDS:
        raise TimeoutError("campaign has entered the reserved finalization window")
    producer_work = managed / "csdk-work"
    producer_output = managed / "csdk-output"
    producer_env = dict(env)
    producer_env["PATH"] = str(toolchain / "bin") + ":" + ":".join(
        str(tool_paths[name].parent)
        for name in ("cc", "cmake", "pkg-config", "perl", "git", "patch")) + ":" + NATIVE_TOOL_RUNTIME_PATH
    command = [sys.executable, "-I", "-B", str(repo / "release/csdk_producer.py"),
               "--work", str(producer_work), "--output", str(producer_output),
               "--toolchain", str(toolchain), "--native-compiler", str(tool_paths["cc"]),
               "--original-archive", str(repo / "release/inputs/csdk.tar.xz"),
               "--spec", str(spec_path), "--cmake", str(tool_paths["cmake"]),
               "--pkg-config", str(tool_paths["pkg-config"]), "--perl", str(tool_paths["perl"]),
               "--git", str(tool_paths["git"])]
    tool_log_dir = managed / "tool-versions"
    tool_log_dir.mkdir()
    remaining_producer_seconds = INNER_PRODUCER_WORK_SECONDS - (
        int(time.time()) - campaign_start)
    if remaining_producer_seconds <= 0:
        raise TimeoutError("campaign has entered the reserved finalization window")
    stdout_path = tool_log_dir / "csdk-producer.stdout.log"
    stderr_path = tool_log_dir / "csdk-producer.stderr.log"
    with stdout_path.open("xb") as stdout, stderr_path.open("xb") as stderr:
        return_code = run_child_with_deadline(
            command, cwd=repo, env=producer_env, stdout=stdout, stderr=stderr,
            timeout=remaining_producer_seconds, label="portable C-SDK producer",
            timeout_record=managed / "csdk-producer-timeout.json",
            ci_cargo_module=ci_cargo)
    if return_code != 0:
        raise RuntimeError("portable C-SDK producer exited with status " + str(return_code))

    post_code_pins = verify_pinned_sources(repo)
    post_git_record = source_commit(repo, expected_head)
    if post_code_pins != code_pins or post_git_record != git_record:
        raise ValueError("protected source checkout changed during candidate production")

    producer_record_path = producer_output / "csdk-producer.json"
    profile_path = producer_output / CANDIDATE["profile_name"]
    candidate_path = producer_output / CANDIDATE["archive_name"]
    producer_record = read_json(producer_record_path, 4 * 1024**2)
    archive_identity = file_identity(candidate_path)
    profile_identity = file_identity(profile_path)
    if (producer_record.get("schema") != "ami-rust-portable-csdk-producer-v1"
            or producer_record.get("status") != "PRODUCED_CSDK_COMPONENT_CANDIDATE_NOT_R1_ACCEPTED"
            or producer_record.get("host") != host
            or producer_record.get("R1_accepted") is not False
            or producer_record.get("baseline_changed") is not False
            or producer_record.get("spec_sha256") != EXPECTED["release/portable-csdk/spec.json"]
            or archive_identity["bytes"] != CANDIDATE["archive_bytes"]
            or archive_identity["sha256"] != CANDIDATE["archive_sha256"]
            or profile_identity["bytes"] != CANDIDATE["profile_bytes"]
            or profile_identity["sha256"] != CANDIDATE["profile_sha256"]
            or producer_record.get("candidate_archive") != {
                "path": CANDIDATE["archive_name"], "bytes": CANDIDATE["archive_bytes"],
                "sha256": CANDIDATE["archive_sha256"]}
            or producer_record.get("profile_sha256") != CANDIDATE["profile_sha256"]):
        raise ValueError("portable C-SDK producer output differs from the frozen candidate identity")
    series = read_json(repo / "release/patches/portable-csdk/series.json")
    expected_patches = [{
        "component": row["component"], "path": row["path"],
        "before_sha256": row["before_sha256"], "after_sha256": row["after_sha256"],
        "patch_sha256": row["patch_sha256"],
    } for row in series.get("patches", [])]
    if producer_record.get("patches") != expected_patches:
        raise ValueError("producer patch receipts differ from the pinned series")
    native_compile = producer_record.get("native_compile", {})
    if (native_compile.get("completed") != 825 or native_compile.get("failure") is not None
            or producer_record.get("native_symbol_entries") != 4515
            or len(producer_record.get("native_members", [])) != 825
            or producer_record.get("source_capsule_sha256")
            != EXPECTED["release/csdk-source/csdk-corresponding-source.tar.xz"]):
        raise ValueError("producer compilation or source-capsule receipt is incomplete")
    verify_native_host_tools_unchanged(tool_records)
    if file_identity(compiler) != clang_identity:
        raise ValueError("pinned ARM clang changed during production")

    # Export only candidate bytes, the producer's profile/receipt, and bounded
    # logs. The source capsule, unpacked LLVM, and build stages stay temporary.
    exported = []
    for source in (candidate_path, profile_path, producer_record_path):
        target = artifact / source.name
        shutil.copyfile(source, target)
        exported.append(file_identity(target))
    receipt = {
        "schema": INNER_SCHEMA,
        "status": "CANDIDATE_ONLY",
        "claim": CLAIM,
        "source": git_record,
        "source_input_sha256": code_pins,
        "source_files": input_identities,
        "portable_csdk_spec_sha256": EXPECTED["release/portable-csdk/spec.json"],
        "resource_policy_sha256": EXPECTED["release/ci-resources.json"],
        "capacity_preflight": capacity,
        "host": {"key": host, "triple": "aarch64-unknown-linux-gnu",
                 "system": platform.platform(), "machine": platform.machine(),
                 "os_release": os_release},
        "python": {"path": str(Path(sys.executable).resolve(strict=True)),
                   "version": sys.version,
                   "sha256": sha256(Path(sys.executable).resolve(strict=True))},
        "llvm": {"archive_pin": LLVM_ARCHIVE, "download": download_record,
                 "extraction": extraction, "profile_receipt": profile_receipt,
                 "clang": clang_identity, "clang_version": clang_version},
        "native_host_tools": tool_records,
        "producer": {"status": producer_record["status"],
                     "receipt_sha256": sha256(producer_record_path),
                     "patches": producer_record.get("patches"),
                     "source_capsule_sha256": producer_record.get("source_capsule_sha256"),
                     "candidate_archive": archive_identity,
                     "candidate_profile": profile_identity},
        "exported_files": exported,
        "limits": {"aggregate_process_tree_rss_bytes": MAX_RSS_BYTES,
                   "managed_workspace_bytes": MAX_WORK_BYTES,
                   "raw_log_bytes": MAX_LOG_BYTES,
                   "per_command_seconds": MAX_PHASE_SECONDS,
                   "producer_deadline_seconds": PRODUCER_WINDOW_SECONDS,
                   "finalization_deadline_seconds": FINALIZATION_DEADLINE_SECONDS,
                   "campaign_seconds": CAMPAIGN_SECONDS,
                   "review_reserve_seconds": REVIEW_RESERVE_SECONDS},
        "source_capsule_exported": False,
        "producer_staging_exported": False,
        "rust_or_cargo_admission": False,
        "sdk_l1_rc4_or_release_acceptance": False,
    }
    write_json(managed / "inner-result.json", receipt)
    write_json(artifact / "inner-result.json", receipt)
    return receipt


def copy_log_tree(work: Path, artifact: Path) -> list[dict]:
    logs, total = [], 0
    destination_root = artifact / "logs"
    for source in sorted(work.rglob("*.log")):
        if source.is_symlink() or not source.is_file():
            raise ValueError("observed log is not a regular file")
        relative = source.relative_to(work)
        size = source.stat().st_size
        source_hash = sha256(source)
        copied = min(size, max(0, MAX_LOG_BYTES - total))
        target = destination_root / relative
        exported_digest = hashlib.sha256()
        written = 0
        if copied:
            target.parent.mkdir(parents=True, exist_ok=True)
            with source.open("rb") as source_stream, target.open("xb") as target_stream:
                while written < copied:
                    block = source_stream.read(min(1024 * 1024, copied - written))
                    if not block:
                        raise OSError("source log changed while it was copied")
                    target_stream.write(block)
                    exported_digest.update(block)
                    written += len(block)
            target_hash = exported_digest.hexdigest()
        else:
            target_hash = None
        logs.append({"path": target.relative_to(artifact).as_posix() if copied else None,
                     "source_bytes": size, "source_sha256": source_hash,
                     "exported_bytes": written, "exported_sha256": target_hash,
                     "truncated": copied != size})
        total += written
    return logs


def safe_directory_bytes(root: Path) -> int:
    total = 0
    for directory, dirs, names in os.walk(root, followlinks=False):
        dirs[:] = [name for name in dirs
                   if not (Path(directory) / name).is_symlink()]
        for name in names:
            path = Path(directory) / name
            try:
                info = path.lstat()
            except FileNotFoundError:
                continue
            if path.is_symlink():
                continue
            if path.is_file():
                total += info.st_size
    return total


def outer_run(repo: Path, managed: Path, outer_output: Path) -> dict:
    validate_nested_deadline_policy()
    OUTER_FAILURE_CONTEXT.clear()
    os_release = read_os_release()
    if (platform.system() != "Linux" or platform.machine().lower() not in {"aarch64", "arm64"}
            or os_release.get("ID") != "ubuntu"
            or os_release.get("VERSION_ID") != "24.04"):
        raise ValueError("outer observer requires Ubuntu 24.04 Linux/AArch64")
    repo = repo.resolve(strict=True)
    managed = managed.resolve(strict=True)
    outer_output = outer_output.resolve(strict=True)
    artifact = outer_output / "artifact"
    if not managed.is_dir() or not outer_output.is_dir() or not artifact.is_dir():
        raise ValueError("preflight must create fresh managed and output roots before checkout")
    if managed == outer_output or managed in outer_output.parents or outer_output in managed.parents:
        raise ValueError("managed and outer-output roots overlap")
    if any(artifact.iterdir()):
        raise ValueError("artifact directory must be fresh")
    source_pins = verify_pinned_sources(repo)
    git_record = source_commit(repo, os.environ.get("GITHUB_SHA", ""))
    ci_cargo = load_module(repo / "release/ci_cargo.py", "_portable_csdk_arm_ci_cargo_outer")
    validate_nested_deadline_policy(
        ci_cargo.PROCESS_ROWS_TIMEOUT_SECONDS, ci_cargo.SUPERVISOR_STOP_GRACE_SECONDS)
    # ci_cargo.Supervisor measures the supervised child tree, not its own
    # Python process. Leave a fixed reserve for this outer observer and add
    # its own peak RSS to the reported child-tree peak after the run.
    ci_cargo.MAX_RSS_BYTES = CHILD_RSS_LIMIT_BYTES
    runtime_dirs = create_outer_runtime_directories(managed)
    log_dir = managed / "observer-logs"
    log_dir.mkdir()
    env = {"HOME": str(runtime_dirs["home"]), "TMPDIR": str(runtime_dirs["tmp"]),
           "TMP": str(runtime_dirs["tmp"]), "TEMP": str(runtime_dirs["tmp"]),
           "PATH": "/usr/bin:/bin:/usr/sbin:/sbin", "LC_ALL": "C", "LANG": "C",
           "TZ": "UTC", "PYTHONNOUSERSITE": "1", "PYTHONDONTWRITEBYTECODE": "1",
           "GIT_TERMINAL_PROMPT": "0", "GIT_CONFIG_NOSYSTEM": "1",
           "GIT_CONFIG_GLOBAL": os.devnull, "GIT_OPTIONAL_LOCKS": "0",
           "GITHUB_SHA": os.environ["GITHUB_SHA"],
           "GITHUB_RUN_ID": os.environ["GITHUB_RUN_ID"],
           "GITHUB_RUN_ATTEMPT": os.environ["GITHUB_RUN_ATTEMPT"],
           "CSDK_CAMPAIGN_START_EPOCH": os.environ["CSDK_CAMPAIGN_START_EPOCH"],
           "CSDK_POLICY_SHA256": os.environ["CSDK_POLICY_SHA256"]}
    supervisor = ci_cargo.Supervisor(managed, outer_output, env, log_dir)
    OUTER_FAILURE_CONTEXT.update({"observer_command": None, "observer_commands": []})
    campaign_start = int(os.environ["CSDK_CAMPAIGN_START_EPOCH"])
    remaining = OUTER_PRODUCER_DEADLINE_SECONDS - (int(time.time()) - campaign_start)
    if remaining <= 0:
        raise TimeoutError("campaign has entered the reserved finalization window")
    script = Path(__file__).resolve(strict=True)
    command = [sys.executable, "-I", "-B", str(script), "--inner",
               "--repo", str(repo), "--managed-root", str(managed),
               "--outer-output", str(outer_output)]
    observer_record, failure = None, None
    observer_commands = []
    observer_parent_peak = 0

    def observer_rss_guard(child_peak: int) -> bool:
        nonlocal observer_parent_peak
        observer_parent_peak = max(
            observer_parent_peak,
            int(resource.getrusage(resource.RUSAGE_SELF).ru_maxrss) * 1024)
        OUTER_FAILURE_CONTEXT.update({
            "observer_parent_peak_rss_bytes": observer_parent_peak,
            "supervised_child_peak_rss_bytes": child_peak,
        })
        return (observer_parent_peak <= OBSERVER_RSS_RESERVE_BYTES
                and observer_parent_peak + child_peak <= MAX_RSS_BYTES)

    try:
        if not observer_rss_guard(0):
            raise RuntimeError("outer observer RSS reserve exceeded before producer start")
        observer_record = supervisor.run(
            command, cwd=repo, label="portable-csdk-arm-producer",
            timeout=min(remaining, OUTER_PRODUCER_DEADLINE_SECONDS),
            rss_guard=observer_rss_guard, cleanup_descendant_groups=True)
    except BaseException as error:
        failure = redacted_error(error, repo, managed)
    observer_commands = list(getattr(supervisor, "commands", []))
    if observer_record is None and observer_commands:
        observer_record = observer_commands[-1]
    observer_parent_peak = max(
        observer_parent_peak,
        int(resource.getrusage(resource.RUSAGE_SELF).ru_maxrss) * 1024)
    combined_peak_rss = supervisor.peak_rss + observer_parent_peak
    OUTER_FAILURE_CONTEXT.update({
        "observer_command": observer_record,
        "observer_commands": observer_commands,
        "observer_parent_peak_rss_bytes": observer_parent_peak,
        "supervised_child_peak_rss_bytes": supervisor.peak_rss,
        "aggregate_process_tree_rss_bytes": combined_peak_rss,
        "managed_workspace_bytes": max(supervisor.peak_workspace, supervisor.managed_bytes()),
        "raw_log_bytes": supervisor.logs_bytes(),
    })
    inner_path = managed / "inner-result.json"
    inner = read_json(inner_path, 4 * 1024**2) if inner_path.is_file() else None
    log_records = copy_log_tree(managed, artifact)
    status = "PREREQUISITE_ONLY" if (
        failure is None and inner is not None
        and inner.get("schema") == INNER_SCHEMA and inner.get("status") == "CANDIDATE_ONLY"
        and observer_record is not None and observer_record.get("stop_reason") is None
        and observer_record.get("exit_code") == 0) else "FAILED"
    if int(time.time()) - campaign_start >= FINALIZATION_DEADLINE_SECONDS:
        status = "FAILED"
        failure = failure or "finalization deadline exceeded before driver receipt"
    peaks = {"aggregate_process_tree_rss_bytes": combined_peak_rss,
             "supervised_child_tree_rss_bytes": supervisor.peak_rss,
             "outer_observer_peak_rss_bytes": observer_parent_peak,
             "managed_workspace_bytes": max(supervisor.peak_workspace, supervisor.managed_bytes()),
             "raw_log_bytes": supervisor.logs_bytes(),
             "observer_command": observer_record,
             "observer_commands": observer_commands,
             "limits": {"aggregate_rss_bytes": MAX_RSS_BYTES,
                        "child_tree_rss_bytes": CHILD_RSS_LIMIT_BYTES,
                        "observer_parent_reserve_bytes": OBSERVER_RSS_RESERVE_BYTES,
                        "observer_parent_guard": "RUSAGE_SELF.ru_maxrss sampled during existing Supervisor polling; child is stopped if reserve is crossed",
                        "workspace_bytes": MAX_WORK_BYTES,
                        "log_bytes": MAX_LOG_BYTES, "inner_phase_seconds": MAX_PHASE_SECONDS,
                        "producer_window_seconds": PRODUCER_WINDOW_SECONDS,
                        "inner_producer_work_deadline_seconds": INNER_PRODUCER_WORK_SECONDS,
                        "inner_producer_cleanup_reserve_seconds": INNER_PRODUCER_CLEANUP_RESERVE_SECONDS,
                        "outer_producer_backup_deadline_seconds": OUTER_PRODUCER_DEADLINE_SECONDS,
                        "outer_cleanup_reserve_seconds": OUTER_CLEANUP_RESERVE_SECONDS}}
    output_bytes = ci_cargo.directory_bytes(artifact)
    if (observer_parent_peak > OBSERVER_RSS_RESERVE_BYTES
            or peaks["aggregate_process_tree_rss_bytes"] > MAX_RSS_BYTES
            or peaks["managed_workspace_bytes"] > MAX_WORK_BYTES
            or peaks["raw_log_bytes"] > MAX_LOG_BYTES
            or output_bytes > ARTIFACT_PAYLOAD_BYTES):
        status = "FAILED"
        failure = failure or "resource or evidence bound exceeded"
    OUTER_FAILURE_CONTEXT.update({"raw_logs": log_records})
    result = {"schema": WORKFLOW_SCHEMA, "status": status, "claim": CLAIM,
              "source": git_record, "driver": file_identity(script),
              "observer": {"kind": "existing ci_cargo.Supervisor",
                           "source_sha256": source_pins["release/ci_cargo.py"]["sha256"],
                           "python_path": str(Path(sys.executable).resolve(strict=True)),
                           "python_sha256": sha256(Path(sys.executable).resolve(strict=True)),
                           "parent_rss_measurement": "RUSAGE_SELF.ru_maxrss in Linux KiB; conservatively added to supervised child-tree peak",
                           "parent_rss_reserve_bytes": OBSERVER_RSS_RESERVE_BYTES},
              "inner_result_sha256": sha256(inner_path) if inner_path.is_file() else None,
              "inner_status": inner.get("status") if inner else None,
              "peaks": peaks, "raw_logs": log_records,
              "artifact_payload_bytes_before_final_workflow_record": output_bytes,
              "artifact_payload_limit_bytes": ARTIFACT_PAYLOAD_BYTES,
              "failure": failure,
              "source_capsule_exported": False, "producer_staging_exported": False,
              "rust_or_cargo_admission": False,
              "sdk_l1_rc4_or_release_acceptance": False}
    record_path = artifact / "driver-result.json"
    encoded = (json.dumps(result, sort_keys=True, indent=2) + "\n").encode()
    if output_bytes + len(encoded) > ARTIFACT_PAYLOAD_BYTES:
        result["status"] = "FAILED"
        result["failure"] = result["failure"] or "final artifact payload exceeds the 127 MiB producer bound"
        encoded = (json.dumps(result, sort_keys=True, indent=2) + "\n").encode()
    with record_path.open("xb") as stream:
        stream.write(encoded)
    final_output_bytes = ci_cargo.directory_bytes(artifact)
    if final_output_bytes > ARTIFACT_PAYLOAD_BYTES:
        result["status"] = "FAILED"
        result["failure"] = (result["failure"]
                             or "final artifact payload exceeds the 127 MiB producer bound")
        with record_path.open("wb") as stream:
            stream.write((json.dumps(result, sort_keys=True, indent=2) + "\n").encode())
        raise ValueError("final artifact payload exceeds the 127 MiB producer bound")
    return result


def write_outer_failure(args: argparse.Namespace, error: BaseException) -> None:
    """Retain a bounded refusal record when preflight made the artifact root."""
    artifact = args.outer_output / "artifact"
    if artifact.is_symlink() or not artifact.is_dir():
        return
    script = Path(__file__).resolve(strict=True)
    result_path = artifact / "driver-result.json"
    if result_path.is_symlink():
        return
    if result_path.is_file():
        try:
            existing = read_json(result_path, 2 * 1024**2)
        except (OSError, ValueError, json.JSONDecodeError):
            existing = {}
        if existing.get("status") == "FAILED":
            return
    context = OUTER_FAILURE_CONTEXT
    try:
        artifact_bytes = safe_directory_bytes(artifact)
    except OSError:
        artifact_bytes = 0
    record = {
        "schema": WORKFLOW_SCHEMA,
        "status": "FAILED",
        "claim": CLAIM,
        "driver": file_identity(script),
        "observer": {"kind": "existing ci_cargo.Supervisor",
                     "parent_rss_reserve_bytes": OBSERVER_RSS_RESERVE_BYTES,
                     "parent_rss_guard": "sampled online during existing Supervisor polling; failures retain observed parent and child peaks"},
        "inner_result_sha256": None,
        "inner_status": None,
        "peaks": {"observer_command": context.get("observer_command"),
                  "observer_commands": context.get("observer_commands", []),
                  "aggregate_process_tree_rss_bytes": context.get("aggregate_process_tree_rss_bytes"),
                  "supervised_child_tree_rss_bytes": context.get("supervised_child_peak_rss_bytes"),
                  "outer_observer_peak_rss_bytes": context.get("observer_parent_peak_rss_bytes"),
                  "managed_workspace_bytes": context.get("managed_workspace_bytes"),
                  "raw_log_bytes": context.get("raw_log_bytes"),
                  "limits": {"aggregate_rss_bytes": MAX_RSS_BYTES,
                             "workspace_bytes": MAX_WORK_BYTES,
                             "log_bytes": MAX_LOG_BYTES,
                             "producer_deadline_seconds": PRODUCER_WINDOW_SECONDS,
                             "finalization_deadline_seconds": FINALIZATION_DEADLINE_SECONDS}},
        "raw_logs": context.get("raw_logs", []),
        "artifact_payload_bytes_before_final_workflow_record": artifact_bytes,
        "artifact_payload_limit_bytes": ARTIFACT_PAYLOAD_BYTES,
        "failure": redacted_error(error, args.repo, args.managed_root),
        "failure_stage": "outer_setup_or_finalization",
        "source_capsule_exported": False,
        "producer_staging_exported": False,
        "rust_or_cargo_admission": False,
        "sdk_l1_rc4_or_release_acceptance": False,
    }
    if result_path.exists():
        with result_path.open("wb") as stream:
            stream.write((json.dumps(record, sort_keys=True, indent=2) + "\n").encode())
    else:
        write_json(result_path, record)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--inner", action="store_true")
    parser.add_argument("--repo", type=Path, required=True)
    parser.add_argument("--managed-root", type=Path, required=True)
    parser.add_argument("--outer-output", type=Path, required=True)
    args = parser.parse_args()
    OUTER_FAILURE_CONTEXT.clear()
    try:
        if args.inner:
            inner_produce(args.repo, args.managed_root, args.outer_output / "artifact",
                          os.environ["GITHUB_SHA"],
                          int(os.environ["CSDK_CAMPAIGN_START_EPOCH"]))
        else:
            result = outer_run(args.repo, args.managed_root, args.outer_output)
            print("CSDK_PRODUCER_STATUS=" + result["status"])
            if result["status"] != "PREREQUISITE_ONLY":
                return 1
        return 0
    except BaseException as error:
        if args.inner:
            try:
                managed = args.managed_root.resolve(strict=True)
                repo = args.repo.resolve(strict=True)
                record = {"schema": INNER_SCHEMA, "status": "FAILED",
                          "claim": CLAIM, "stage": "exception",
                          "failure": redacted_error(error, repo, managed),
                          "source_capsule_exported": False,
                          "producer_staging_exported": False,
                          "sdk_l1_rc4_or_release_acceptance": False}
                timeout_path = managed / "csdk-producer-timeout.json"
                if (not timeout_path.is_symlink() and timeout_path.is_file()
                        and timeout_path.stat().st_size <= 1024 * 1024):
                    timeout_receipt = read_json(timeout_path, 1024 * 1024)
                    if (timeout_receipt.get("schema")
                            == "ami-rust-portable-csdk-producer-timeout-v1"
                            and timeout_receipt.get("status") == "FAILED"
                            and timeout_receipt.get("candidate_accepted") is False):
                        record["producer_timeout_receipt"] = timeout_receipt
                        record["producer_timeout_receipt_sha256"] = sha256(timeout_path)
                write_json(managed / "inner-result.json", record)
                write_json(args.outer_output / "artifact" / "inner-result.json", record)
            except BaseException:
                pass
        else:
            try:
                write_outer_failure(args, error)
            except BaseException:
                pass
        print("portable C-SDK candidate producer failed: " + str(error)[:1000], file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
