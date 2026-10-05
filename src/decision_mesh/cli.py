"""Local CLI; source documents and credentials never belong in command arguments."""

from __future__ import annotations

import argparse
import hmac
import json
import sys
from dataclasses import asdict
from datetime import UTC, datetime
from pathlib import Path

from .capture import MAX_EVENT_BYTES, ensure_spool_dir, owner_file_lock, parse_json
from .diagnostics import doctor, export_report
from .producer import ExplicitProducer, ProducerDocument, enroll_producer
from .runtime import Runtime
from .runtime_control import (
    RuntimeErrorCode,
    RuntimePaths,
    default_data_dir,
    open_inbox,
    setup_action,
    stop_runtime,
)
from .storage import SQLiteStore


class Parser(argparse.ArgumentParser):
    def error(self, message):
        # argparse's usual error includes untrusted argv (possibly a pasted token).
        raise RuntimeErrorCode("invalid_arguments")


def parser():
    result = Parser(
        prog="decisionmesh",
        description="Local decision observations. Respond in the original host.",
    )
    commands = result.add_subparsers(dest="command", required=True, parser_class=Parser)

    def command(name, parent=commands):
        item = parent.add_parser(name)
        item.add_argument("--data-dir", type=Path, default=None)
        return item

    opening = command("open")
    opening.add_argument("reference", nargs="?")
    opening.add_argument(
        "--local-only",
        action="store_true",
        help="If starting a runtime, disable credential access and sends.",
    )
    running = command("run")
    running.add_argument("--local-only", action="store_true")
    command("stop")
    diagnostic = command("doctor")
    diagnostic.add_argument("--export", type=Path)
    setup = command("setup")
    setup.add_argument(
        "--status",
        action="store_true",
        help="Print redacted setup status without opening a browser.",
    )
    setup.add_argument("--local-only", action="store_true")
    setup.add_argument(
        "--verify-local",
        action="store_true",
        help="Explicitly verify this local runtime and synthetic capture/import; native support stays unverified.",
    )
    setup.add_argument(
        "--reconcile",
        action="store_true",
        help="Explicitly retry configuration validation and policy publication.",
    )
    setup.add_argument("--windows-integration", choices=("install", "repair", "remove"))
    setup.add_argument("--autostart", action=argparse.BooleanOptionalAction, default=None)
    setup.add_argument("--shortcut", action=argparse.BooleanOptionalAction, default=None)
    setup.add_argument("--apply-plan", help="Apply the exact previously displayed plan digest.")
    producer = commands.add_parser("producer")
    operations = producer.add_subparsers(dest="operation", required=True, parser_class=Parser)
    for name in ("enroll", "create", "update", "resolve", "withdraw"):
        command(name, operations)
    backup = command("backup")
    backup.add_argument("--destination", type=Path, required=True)
    restore = command("restore")
    restore.add_argument("--backup", type=Path, required=True)
    return result


def _json(value, stream):
    stream.write(json.dumps(value, ensure_ascii=True, separators=(",", ":")) + "\n")


def _maintenance(args, paths):
    ensure_spool_dir(paths.root)
    with owner_file_lock(paths.lock, timeout=0):
        if args.command == "backup":
            if not paths.database.exists():
                raise RuntimeErrorCode("storage_absent")
            destination = args.destination
            if not destination.is_absolute() or destination.exists() or destination.is_symlink():
                raise RuntimeErrorCode("new_absolute_backup_path_required")
            with SQLiteStore(paths.database) as store:
                store.backup(destination)
            return {"ok": True, "status": "backup_created", "includes_credentials": False}
        if (
            paths.database.exists()
            or not args.backup.is_absolute()
            or any(entry.name != paths.lock.name for entry in paths.root.iterdir())
        ):
            raise RuntimeErrorCode("restore_requires_new_data_directory")
        with SQLiteStore.restore_backup(
            args.backup, paths.database, now=datetime.now(UTC)
        ) as store:
            store.publish_capture_policy(paths.policy)
        return {
            "ok": True,
            "status": "restored_notifications_disabled",
            "reconciliation_required": True,
        }


def _windows_setup(args, paths):
    from .windows_setup import build_current_user_integration

    if args.status or args.local_only:
        raise RuntimeErrorCode("incompatible_setup_arguments")
    ensure_spool_dir(paths.root)
    with owner_file_lock(paths.lock, timeout=0):
        manager = build_current_user_integration(paths.root)
        plan = manager.plan(
            operation=args.windows_integration, autostart=args.autostart, shortcut=args.shortcut
        )
        if args.apply_plan is None:
            return {"ok": True, "status": "plan_only", "plan": asdict(plan)}
        if not hmac.compare_digest(args.apply_plan, plan.snapshot):
            raise RuntimeErrorCode("integration_plan_changed")
        manager.apply(plan)
        with SQLiteStore(paths.database) as store:
            current = store.get_settings()
            if current.autostart != plan.autostart:
                store.update_settings(
                    current.revision, {"autostart": plan.autostart}, now=datetime.now(UTC)
                )
                store.publish_capture_policy(paths.policy)
        return {
            "ok": True,
            "status": "owned_integration_applied",
            "autostart": plan.autostart,
            "shortcut": plan.shortcut,
            "actual_logon_launch": "unverified",
        }


def main(argv=None, *, stdin=None, stdout=None, stderr=None):
    source, output, errors = stdin or sys.stdin, stdout or sys.stdout, stderr or sys.stderr
    try:
        args = parser().parse_args(argv)
        paths = RuntimePaths(args.data_dir or default_data_dir())
        if args.command == "run":
            Runtime(paths.root, local_only=args.local_only).serve()
            return 0
        if args.command == "open":
            open_inbox(paths, reference=args.reference, local_only=args.local_only)
            _json({"ok": True, "status": "browser_opened"}, output)
        elif args.command == "stop":
            active = stop_runtime(paths)
            _json({"ok": True, "status": "stopping" if active else "not_running"}, output)
        elif args.command == "doctor":
            report = doctor(paths)
            if args.export:
                export_report(report, args.export)
            _json(report, output)
        elif args.command == "setup":
            selected = sum(
                (args.status, args.verify_local, args.reconcile, bool(args.windows_integration))
            )
            if selected > 1:
                raise RuntimeErrorCode("incompatible_setup_arguments")
            if args.verify_local or args.reconcile:
                if (
                    args.apply_plan is not None
                    or args.autostart is not None
                    or args.shortcut is not None
                ):
                    raise RuntimeErrorCode("incompatible_setup_arguments")
                result = setup_action(
                    paths,
                    action="verification" if args.verify_local else "reconcile",
                    local_only=args.local_only,
                )
                _json(result, output)
                return 0 if result["ok"] else 1
            if args.windows_integration:
                _json(_windows_setup(args, paths), output)
            elif (
                args.apply_plan is not None
                or args.autostart is not None
                or args.shortcut is not None
            ):
                raise RuntimeErrorCode("integration_operation_required")
            elif args.status:
                report = doctor(paths)
                _json(
                    {
                        key: report[key]
                        for key in (
                            "setup",
                            "secret_backend",
                            "native_support",
                            "hook_trust",
                            "verification_scope",
                            "environment_verified",
                            "local_capture_verified",
                        )
                    },
                    output,
                )
            else:
                open_inbox(paths, local_only=args.local_only)
                _json(
                    {
                        "ok": True,
                        "status": "browser_opened",
                        "next": "Open Settings to configure optional Telegram. Native support remains unverified.",
                    },
                    output,
                )
        elif args.command == "producer":
            if args.operation == "enroll":
                ensure_spool_dir(paths.root)
                enrollment = enroll_producer(paths.producer)
                _json(
                    {
                        "ok": True,
                        "status": "enrolled",
                        "producer_id": enrollment.producer_id,
                        "runtime_started": False,
                    },
                    output,
                )
            else:
                raw = getattr(source, "buffer", source).read(MAX_EVENT_BYTES + 1)
                document = ProducerDocument.model_validate(parse_json(raw, MAX_EVENT_BYTES))
                producer = ExplicitProducer(paths.producer, policy_path=paths.policy)
                receipt = getattr(producer, args.operation)(document)
                _json(
                    {
                        "ok": True,
                        "accepted_to_spool": receipt.accepted_to_spool,
                        "ingested": False,
                        "event_id": receipt.event_id,
                        "revision": receipt.revision,
                        "idempotency_key": receipt.idempotency_key,
                        "duplicate": receipt.duplicate,
                    },
                    output,
                )
        elif args.command in {"backup", "restore"}:
            _json(_maintenance(args, paths), output)
        return 0
    except KeyboardInterrupt:
        _json({"ok": False, "error": "interrupted"}, errors)
        return 130
    except Exception:  # noqa: BLE001 - preserve a fixed redacted boundary for local I/O and injected peers
        _json(
            {
                "ok": False,
                "error": "command_failed",
                "help": "Check command syntax, owned paths and setup status. Reporting may require native permission; do not retry recursively for telemetry.",
            },
            errors,
        )
        return 1
