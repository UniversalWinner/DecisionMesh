"""Proposed hosted Windows standard-user smoke; unqualified until a real run.

Account/profile operations require --run-hosted and explicit hosted-runner guards.
No browser, native integration, host hook, service/policy change or Telegram send.
"""
from __future__ import annotations

import argparse
import ctypes
import hashlib
import importlib.util
import json
import os
import platform
import secrets
import stat
import string
import subprocess
import sys
import zipfile
from email.parser import BytesParser
from pathlib import Path
from types import SimpleNamespace
from typing import Any

ADMIN = "S-1-5-32-544"
SYSTEM = "S-1-5-18"


class QualificationError(RuntimeError):
    """Fixed redacted error codes."""

    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


def require(value: object, code: str) -> None:
    if not value:
        raise QualificationError(code)


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def safe_path(path: Path, *, missing: bool = False) -> Path:
    require(path.is_absolute() and not str(path).startswith(("\\\\", "//")), "local_path_required")
    require(".." not in path.parts, "noncanonical_path")
    for part in (path, *path.parents):
        try:
            info = part.lstat()
        except FileNotFoundError:
            require(missing and part == path, "missing_ancestor")
            continue
        require(not stat.S_ISLNK(info.st_mode) and
                not getattr(info, "st_file_attributes", 0) & 1024, "reparse_path")
    return path


def regular(path: Path) -> None:
    safe_path(path)
    info = path.stat()
    require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1, "regular_single_link_required")


def runner_guard(env: dict[str, str], platform: str, enabled: bool,
                 fixture: Path, *, existing: bool = False) -> None:
    require(enabled and platform == "nt", "explicit_windows_execution_required")
    require(all(env.get(k) == v for k, v in {
        "GITHUB_ACTIONS": "true", "RUNNER_ENVIRONMENT": "github-hosted", "RUNNER_OS": "Windows"
    }.items()), "hosted_runner_required")
    base = Path(env.get("RUNNER_TEMP", ""))
    require(base.is_absolute() and fixture.parent == base, "fixture_outside_runner_temp")
    suffix = fixture.name.removeprefix("decisionmesh-standard-user-")
    require(fixture.name == "decisionmesh-standard-user-" + suffix and len(suffix) == 32
            and all(c in string.hexdigits.lower()[:16] for c in suffix), "fixture_name_invalid")
    safe_path(fixture, missing=not existing)
    require(fixture.exists() == existing, "fresh_fixture_required")


def validate_token(token: dict, expected_sid: str, *, parent: bool = False) -> None:
    require(token.get("sid") == expected_sid and expected_sid != SYSTEM, "token_sid_mismatch")
    require(token.get("token_type") == 1 and isinstance(token.get("groups"), list),
            "token_evidence_incomplete")
    groups = token["groups"]
    require(all(isinstance(g, dict) and isinstance(g.get("sid"), str)
                and type(g.get("attributes")) is int for g in groups), "token_groups_invalid")
    memberships = {g["sid"] for g in groups}
    if parent:
        require(ADMIN in memberships and token.get("elevated") is True, "admin_parent_required")
    else:
        require(ADMIN not in memberships, "admin_membership_forbidden")
        require(token.get("elevated") is False and token.get("elevation_type") == 1
                and token.get("integrity") == "S-1-16-8192", "standard_token_required")


def load_exact(path: Path, name: str) -> Any:
    regular(path)
    spec = importlib.util.spec_from_file_location(name, path)
    require(spec is not None and spec.loader is not None, "helper_unavailable")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module



def offline_wheel(path: Path) -> None:
    """Pip --no-index still permits direct URLs; reject those before staging."""
    with zipfile.ZipFile(path) as archive:
        entries = [p for p in archive.infolist() if p.filename.endswith(".dist-info/METADATA")]
        require(len(entries) == 1 and entries[0].file_size <= 1024 * 1024,
                "wheel_metadata_invalid")
        metadata = BytesParser().parsebytes(archive.read(entries[0]))
        require(all("@" not in requirement
                    for requirement in metadata.get_all("Requires-Dist", [])),
                "direct_dependency_url_forbidden")


def validate_inputs(value: dict, fixture: Path) -> list[tuple[str, Path, str]]:
    require(set(value) == {"schema_version", "python", "wheel", "checker", "wheelhouse"}
            and value["schema_version"] == 1, "input_manifest_invalid")
    require(isinstance(value["wheelhouse"], list) and 1 <= len(value["wheelhouse"]) <= 100,
            "wheelhouse_bounds")
    rows = []
    for label, item in [("python", value["python"]), ("wheel", value["wheel"]),
                        ("checker", value["checker"])] + [
                            ("dependency", x) for x in value["wheelhouse"]]:
        require(isinstance(item, dict) and set(item) == {"path", "sha256"}, "input_entry_invalid")
        path = Path(item["path"])
        regular(path)
        require(not path.is_relative_to(fixture) and path.stat().st_size <= 128 * 1024 * 1024,
                "input_path_invalid")
        require(isinstance(item["sha256"], str) and len(item["sha256"]) == 64
                and digest(path) == item["sha256"], "input_hash_mismatch")
        if label in {"wheel", "dependency"}:
            require(path.suffix == ".whl", "wheel_required")
            offline_wheel(path)
        rows.append((label, path, item["sha256"]))
    wheels = [p.name.casefold() for label, p, _ in rows if label in {"wheel", "dependency"}]
    require(len(wheels) == len(set(wheels)), "duplicate_wheel_name")
    require(Path(value["python"]["path"]).name.casefold() == "python.exe", "python_required")
    return rows


def target_environment(profile: Path, fixture: Path, system_root: Path,
                       python: Path) -> dict[str, str]:
    return {
        "SystemRoot": str(system_root), "WINDIR": str(system_root),
        "COMSPEC": str(system_root / "System32/cmd.exe"),
        "PATH": str(python.parent) + os.pathsep + str(system_root / "System32"),
        "USERPROFILE": str(profile), "LOCALAPPDATA": str(profile / "AppData/Local"),
        "APPDATA": str(profile / "AppData/Roaming"),
        "TEMP": str(profile / "AppData/Local/Temp"), "TMP": str(profile / "AppData/Local/Temp"),
        "PYTHONDONTWRITEBYTECODE": "1", "PYTHONNOUSERSITE": "1",
        "PIP_CONFIG_FILE": os.devnull, "PIP_NO_INDEX": "1",
        "PIP_FIND_LINKS": str(fixture / "input/wheels"), "PIP_NO_CACHE_DIR": "1",
        "PIP_DISABLE_PIP_VERSION_CHECK": "1", "GITHUB_ACTIONS": "true",
        "RUNNER_ENVIRONMENT": "github-hosted", "RUNNER_OS": "Windows",
        "RUNNER_TEMP": str(fixture.parent),
    }


def fixture_cleanup(fixture: Path, identity: tuple[int, int],
                    expected: dict[str, str]) -> None:
    safe_path(fixture)
    info = fixture.stat()
    require((info.st_dev, info.st_ino) == identity, "fixture_identity_changed")
    files = {}
    directories = []
    for path in fixture.rglob("*"):
        safe_path(path)
        if path.is_dir():
            directories.append(path)
        else:
            regular(path)
            files[path.relative_to(fixture).as_posix()] = digest(path)
    require(files == expected, "fixture_content_changed")
    allowed_dirs = {parent.as_posix() for name in expected
                    for parent in Path(name).parents if str(parent) != "."}
    allowed_dirs.add("out")
    require({p.relative_to(fixture).as_posix() for p in directories} == allowed_dirs,
            "fixture_foreign_directory")
    for name in sorted(expected):
        path = fixture / name
        regular(path)
        require(digest(path) == expected[name], "fixture_changed_during_cleanup")
        path.unlink()
    for path in sorted(directories, key=lambda p: len(p.parts), reverse=True):
        safe_path(path)
        path.rmdir()
    fixture.rmdir()


def prepare_fixture(fixture: Path, rows: list, parent_sid: str,
                    sid: str, api: Any, profile: Path) -> tuple[dict, tuple[int, int]]:
    fixture.mkdir(exist_ok=False)
    api.protect(fixture, parent_sid, {parent_sid: "FA", sid: "GRGX"})
    for relative in ("input/wheels", "input/tools/release", "out"):
        (fixture / relative).mkdir(parents=True, exist_ok=True)
    api.protect(fixture / "out", parent_sid, {parent_sid: "FA", sid: "FA"})
    staged = {}
    for label, path, hashed in rows:
        if label == "python":
            continue
        relative = ("input/tools/release/check_python_distribution.py" if label == "checker"
                    else "input/wheels/" + path.name)
        (fixture / relative).write_bytes(path.read_bytes())
        require(digest(fixture / relative) == hashed, "copy_hash_mismatch")
        staged[relative] = hashed
    for name in ("check_windows_standard_user.py", "windows_standard_user_native.py"):
        source = Path(__file__).parent / name
        regular(source)
        relative = "input/tools/release/" + name
        (fixture / relative).write_bytes(source.read_bytes())
        staged[relative] = digest(source)
    data = {"sid": sid, "profile": str(profile), "inputs": staged,
            "python": next({"path": str(p), "sha256": h} for k, p, h in rows if k == "python"),
            "wheel": next(p.name for k, p, _ in rows if k == "wheel")}
    (fixture / "input/config.json").write_text(json.dumps(data), encoding="utf-8")
    staged["input/config.json"] = digest(fixture / "input/config.json")
    info = fixture.stat()
    return staged, (info.st_dev, info.st_ino)


def execute(fixture: Path, inputs: dict, api: Any, env: dict[str, str],
            *, enabled: bool, platform: str = os.name) -> dict:
    """Own one fresh account and fixture. Failure never grants cleanup authority."""
    runner_guard(env, platform, enabled, fixture)
    rows = validate_inputs(inputs, fixture)
    parent = api.preflight()
    validate_token(parent, parent["sid"], parent=True)
    name, marker = "dmq" + fixture.name[-16:], "DecisionMesh qualification " + fixture.name[-32:]
    require(api.account(name) is None, "account_already_exists")
    password = ctypes.create_unicode_buffer("Aa1!" + secrets.token_urlsafe(36))
    created = attempted_profile = attempted_account = False
    account = profile = token = process = job = staged = identity = profile_identity = None
    phase = "account_creation"
    result = {"status": "FAILED", "cleanup_complete": False, "scope": "hosted_standard_user_local_core"}
    try:
        attempted_account = True
        api.add_account(name, password, marker)
        created = True
        account = api.account(name)
        require(account is not None and account["name"] == name and account["comment"] == marker,
                "new_account_identity_unproven")
        phase = "interactive_logon"
        token = api.logon(name, password)
        validate_token(api.token_info(token), account["sid"])
        phase = "profile_create"
        attempted_profile = True
        profile = api.create_profile(name, account["sid"])
        phase = "profile_path_validation"
        safe_path(profile)
        phase = "profile_identity"
        info = profile.stat()
        profile_identity = (info.st_dev, info.st_ino)
        phase = "profile_registry_binding"
        require(api.profile_path(account["sid"]).resolve() == profile.resolve(),
                "profile_binding_mismatch")
        phase = "fixture_staging"
        staged, identity = prepare_fixture(fixture, rows, parent["sid"], account["sid"], api, profile)
        python = Path(inputs["python"]["path"])
        child_env = target_environment(profile, fixture, Path(env["SystemRoot"]), python)
        argv = [str(python), "-I", "-B",
                str(fixture / "input/tools/release/check_windows_standard_user.py"),
                "--child", "--run-hosted", "--fixture-root", str(fixture)]
        phase = "profile_logon_process_creation"
        process = api.launch(name, password, argv, child_env, profile)
        validate_token(api.token(process.process), account["sid"])
        job = api.job(process.process)
        phase = "child_execution"
        api.resume(process.thread)
        require(api.wait(process.process, 600_000), "child_timeout")
        require(api.exit_code(process.process) == 0, "child_failed")
        require(api.job_empty(job), "owned_descendants_remain")
        outcome = fixture / "out/result.json"
        regular(outcome)
        require(outcome.stat().st_size < 128 * 1024, "result_bounds")
        observed = json.loads(outcome.read_text(encoding="utf-8"))
        require(observed.get("status") == "PASS" and observed.get("sid") == account["sid"]
                and observed.get("runtime_exited") is True
                and observed.get("lifetime_lock_released") is True, "child_result_invalid")
        staged["out/result.json"] = digest(outcome)
        result.update(status="PASS", child=observed, parent=parent)
    except BaseException as error:  # noqa: BLE001 - project only bounded diagnostics
        result["status"] = "FAILED_OR_UNSUPPORTED"
        result["failed_phase"] = phase
        result["failure"] = api.diagnostic(error, phase)
    finally:
        ctypes.memset(ctypes.addressof(password), 0, ctypes.sizeof(password))
        cleanup_phase = "cleanup_process_exit"
        try:
            if process:
                if job:
                    if not api.job_empty(job, timeout=0):
                        api.terminate(job, job=True)
                    require(api.wait(process.process, 10_000) and api.job_empty(job),
                            "owned_processes_not_exited")
                elif not api.wait(process.process, 0):
                    api.terminate(process.process, job=False)  # Our still-suspended creation handle.
                    require(api.wait(process.process, 10_000), "suspended_child_not_exited")
                cleanup_phase = "cleanup_process_handles"
                api.close(process.thread)
                api.close(process.process)
            if job:
                cleanup_phase = "cleanup_job_handle"
                api.close(job)
            if token:
                cleanup_phase = "cleanup_logon_token"
                api.close(token)
                token = None
            if attempted_account and not created:
                cleanup_phase = "cleanup_creation_state"
                require(api.account(name) is None, "failed_creation_account_state_uncertain")
            if created:
                cleanup_phase = "cleanup_account_identity"
                require(account is not None and api.account(name) == account,
                        "account_cleanup_identity_changed")
                if attempted_profile:
                    cleanup_phase = "cleanup_profile_proof"
                    require(profile is not None, "profile_cleanup_unproven")
                    cleanup_phase = "cleanup_profile_path"
                    safe_path(profile)
                    cleanup_phase = "cleanup_profile_identity"
                    info = profile.stat()
                    require((info.st_dev, info.st_ino) == profile_identity,
                            "profile_identity_changed")
                    cleanup_phase = "cleanup_profile_deletion"
                    api.delete_profile(account["sid"], profile)
                cleanup_phase = "cleanup_account_deletion"
                api.delete_account(name, expected_sid=account["sid"],
                                   expected_marker=account["comment"])
                cleanup_phase = "cleanup_account_absence"
                require(api.account(name) is None, "account_cleanup_not_observed")
            if staged is not None:
                cleanup_phase = "cleanup_fixture"
                fixture_cleanup(fixture, identity, staged)
            cleanup_phase = "cleanup_fixture_absence"
            require(not fixture.exists(), "fixture_cleanup_incomplete")
            result["cleanup_complete"] = True
        except BaseException as error:  # noqa: BLE001 - retain separately bounded cleanup evidence
            result["status"] = "FAILED_CLEANUP_UNPROVEN"
            result["cleanup_complete"] = False
            result["cleanup_failed_phase"] = cleanup_phase
            result["cleanup_failure"] = api.diagnostic(error, cleanup_phase)
        if created:
            result["fixture_account"] = name
            result["fixture_sid"] = account["sid"] if account else None
    return result


def child_smoke(fixture: Path, api: Any, env: dict[str, str]) -> dict:
    runner_guard(env, os.name, True, fixture, existing=True)
    regular(fixture / "input/config.json")
    config = json.loads((fixture / "input/config.json").read_text(encoding="utf-8"))
    token = api.token()
    validate_token(token, config["sid"])
    profile = Path(config["profile"])
    safe_path(profile)
    require(api.profile_path(config["sid"]).resolve() == profile.resolve()
            and api.loaded_profile(config["sid"])
            and Path(env["USERPROFILE"]).resolve() == profile.resolve()
            and Path(env["LOCALAPPDATA"]).resolve() == (profile / "AppData/Local").resolve(),
            "target_profile_unproven")
    for relative, hashed in config["inputs"].items():
        path = fixture / relative
        require(path.is_relative_to(fixture), "staged_path_escape")
        regular(path)
        require(digest(path) == hashed, "staged_input_changed")
    require(Path(sys.executable).resolve() == Path(config["python"]["path"]).resolve()
            and sys.version_info >= (3, 12), "child_interpreter_mismatch")
    require(digest(Path(config["python"]["path"])) == config["python"]["sha256"],
            "interpreter_changed")
    temporary = Path(env["TEMP"])
    safe_path(temporary, missing=not temporary.exists())
    require(temporary.is_relative_to(profile), "temporary_path_outside_profile")
    temporary.mkdir(exist_ok=True)
    checker = load_exact(fixture / "input/tools/release/check_python_distribution.py", "checked_smoke")
    require(Path(config["wheel"]).name == config["wheel"]
            and ("input/wheels/" + config["wheel"]) in config["inputs"], "wheel_path_invalid")
    wheel = fixture / "input/wheels" / config["wheel"]
    inspected = checker.inspect_archive(wheel)
    work = profile / "AppData/Local" / fixture.name
    require(not work.exists(), "fresh_user_work_required")
    real_run, runtime = subprocess.run, None
    proof = {"runtime_exited": False, "lifetime_lock_released": False,
             "installed_package_bytes_equal": False}
    def observed_run(args: list, **kwargs: Any) -> Any:
        nonlocal runtime
        command = [str(x) for x in args]
        child_env = kwargs.get("env", {})
        require(child_env.get("PIP_NO_INDEX") == "1"
                and child_env.get("PIP_FIND_LINKS") == str(fixture / "input/wheels"),
                "offline_environment_required")
        completed = real_run(args, **kwargs)
        if completed.returncode == 0 and command[-2:] == ["pip", "check"]:
            package = {p: h for p, h in inspected["members"].items()
                       if p.startswith("decision_mesh/")}
            require(package and all(digest(work / "environment/Lib/site-packages" / p) == h
                                    for p, h in package.items()), "installed_package_changed")
            proof["installed_package_bytes_equal"] = True
        if completed.returncode == 0 and "--verify-local" in command and runtime is None:
            metadata = json.loads((work / "user-data/runtime.json").read_text(encoding="utf-8"))
            runtime = api.runtime_handle(metadata["port"], config["sid"], Path(config["python"]["path"]))
            validate_token(api.token(runtime), config["sid"])
        if "stop" in command:
            require(completed.returncode == 0 and runtime is not None
                    and api.wait(runtime, 10_000) and api.exit_code(runtime) == 0,
                    "actual_runtime_exit_unproven")
            probe = (
                "from pathlib import Path; from decision_mesh.capture import owner_file_lock; "
                "import sys; "
                "lock=owner_file_lock(Path(sys.argv[1]),timeout=0); "
                "lock.__enter__(); lock.__exit__(None,None,None)"
            )
            checked = real_run([str(work / "environment/Scripts/python.exe"), "-I", "-B",
                                "-c", probe, str(work / "user-data/runtime.lock")],
                               cwd=work, env=child_env, capture_output=True, timeout=20)
            require(checked.returncode == 0, "lifetime_lock_not_released")
            proof.update(runtime_exited=True, lifetime_lock_released=True)
        return completed
    checker.subprocess = SimpleNamespace(run=observed_run)
    try:
        smoke = checker.smoke_install(wheel, work)
        require(all(proof.values()), "runtime_proof_missing")
        return {"status": "PASS", "sid": config["sid"], "token": token, "profile": str(profile),
                "wheel_sha256": digest(wheel), "smoke": smoke, **proof,
                "python_version": sys.version.split()[0], "platform": platform.platform(),
                "limits": ["No native host/channel/browser/logon/sleep qualification",
                           "Hosted Windows Server standard child; consumer Windows/UAC unqualified"]}
    finally:
        if runtime:
            api.close(runtime)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--run-hosted", action="store_true")
    parser.add_argument("--fixture-root", type=Path, required=True)
    parser.add_argument("--input-manifest", type=Path)
    parser.add_argument("--child", action="store_true", help=argparse.SUPPRESS)
    args = parser.parse_args()
    result = {"status": "REFUSED_OR_FAILED"}
    try:
        runner_guard(os.environ, os.name, args.run_hosted, args.fixture_root, existing=args.child)
        if not args.child:
            report = args.fixture_root.with_name(args.fixture_root.name + "-result.json")
            safe_path(report, missing=True)
            require(not report.exists(), "new_report_required")
        native = load_exact(Path(__file__).with_name("windows_standard_user_native.py"),
                            "standard_user_native").Native()
        if args.child:
            result = child_smoke(args.fixture_root, native, dict(os.environ))
            with (args.fixture_root / "out/result.json").open("x", encoding="utf-8") as output:
                json.dump(result, output)
        else:
            require(args.input_manifest is not None, "input_manifest_required")
            regular(args.input_manifest)
            require(args.input_manifest.stat().st_size <= 128 * 1024, "manifest_bounds")
            inputs = json.loads(args.input_manifest.read_text(encoding="utf-8"))
            result = execute(args.fixture_root, inputs, native, dict(os.environ), enabled=True)
            report = args.fixture_root.with_name(args.fixture_root.name + "-result.json")
            with report.open("x", encoding="utf-8") as output:
                json.dump(result, output, indent=2)
    except BaseException:  # noqa: BLE001 - public CLI must never print credentials or raw errors
        result = {"status": "REFUSED_OR_FAILED"}
        # Fixed output only. Never print native arguments, child output or exceptions.
    print(json.dumps({"status": result["status"],
                      "cleanup_complete": result.get("cleanup_complete", False)}))
    return 0 if result["status"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
