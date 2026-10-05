"""Inspect public Python archives and smoke-test a wheel in a disposable environment.

This checker never publishes, opens a browser, reads credentials or sends notifications.
The caller chooses a NEW work directory; it is retained for evidence, not deleted.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import stat
import subprocess
import tarfile
import time
import venv
import zipfile
from pathlib import Path, PurePosixPath, PureWindowsPath

ROOT = Path(__file__).resolve().parents[2]
PUBLIC_ROOT = {
    ".gitignore",
    "pyproject.toml",
    "LICENSE",
    "README.md",
    "SECURITY.md",
    "CONTRIBUTING.md",
    "VISION.md",
    "PKG-INFO",
}
REQUIRED_RESOURCES = {
    "ui/templates/inbox.html",
    "ui/static/app.js",
    "ui/static/app.css",
    "resources/decision-mesh/SKILL.md",
    "resources/decision-mesh/producer-reference.md",
    "resources/decision-mesh/example-request.json",
}
PRIVATE_MARKERS = (b"-----begin private key-----",)


def private_markers() -> tuple[bytes, ...]:
    """Add local private paths without embedding a developer identity in source."""
    try:
        extra = json.loads(os.environ.get("DECISIONMESH_PRIVATE_PATHS", "[]"))
    except ValueError:
        raise ValueError("invalid_private_path_configuration") from None
    if not isinstance(extra, list) or not all(isinstance(value, str) for value in extra):
        raise ValueError("invalid_private_path_configuration")
    markers = set(PRIVATE_MARKERS)
    for value in [str(ROOT), str(Path.home()), *extra]:
        path = value.replace("\\", "/").rstrip("/")
        if (
            not (PurePosixPath(path).is_absolute() or PureWindowsPath(path).is_absolute())
            or any(part in {"", ".", ".."} for part in path.lstrip("/").split("/"))
            or any(char in path for char in "\x00\r\n")
        ):
            raise ValueError("invalid_private_path_configuration")
        for spelling in (path, path.replace("/", "\\"), path.replace("/", "\\\\")):
            try:
                markers.add(spelling.casefold().encode("utf-8"))
            except UnicodeEncodeError:
                raise ValueError("invalid_private_path_configuration") from None
    return tuple(sorted(markers))


class _OriginalPathTarInfo(tarfile.TarInfo):
    """Retain parser path assignments before tarfile trims directory names.

    This includes effective PAX/GNU names without replacing tarfile's parser.
    """

    def __init__(self, name=""):
        self.original_names = []
        super().__init__(name)

    def __setattr__(self, name, value):
        if name in {"name", "path"} and isinstance(value, str) and value:
            self.original_names.append(value)
        super().__setattr__(name, value)

    def _apply_pax_info(self, pax_headers, encoding, errors):
        if "path" in pax_headers:
            # A PAX path replaces the fixed header fallback. Keep its spelling
            # before tarfile strips directory terminators from the assignment.
            self.original_names = [pax_headers["path"]]
        super()._apply_pax_info(pax_headers, encoding, errors)

    def _proc_gnulong(self, archive):
        member = super()._proc_gnulong(archive)
        if self.type == tarfile.GNUTYPE_LONGNAME:
            # The parser assigns the complete GNU name, then (for directories)
            # a version with a terminator removed. Discard earlier fallbacks.
            count = 2 if member.isdir() else 1
            member.original_names = member.original_names[-count:]
        return member


def inspect_archive(path: Path) -> dict:
    """No extraction; inspect paths, regular types, scope and required resources."""
    members: dict[str, bytes] = {}
    directories: set[str] = set()
    wheel = path.suffix == ".whl"
    markers = private_markers()

    def member_path(name: str, *, directory: bool = False) -> PurePosixPath:
        # Validate the original archive spelling BEFORE normalization/root removal.
        # One directory terminator is valid; empty/dot/traversal components are not.
        raw = name[:-1] if directory and name.endswith("/") else name
        if (
            not raw
            or "\\" in raw
            or "\x00" in raw
            or any(part in {"", ".", ".."} or ":" in part for part in raw.split("/"))
        ):
            raise ValueError("unsafe_archive_path")
        p = PurePosixPath(raw)
        if p.is_absolute() or str(p) != raw:
            raise ValueError("unsafe_archive_path")
        return p

    def add(name, body):
        p = member_path(name)
        if name in members or len(body) > 8 * 1024 * 1024:
            raise ValueError("invalid_archive_member")
        if "__pycache__" in p.parts or p.suffix in {".pyc", ".pyo"}:
            raise ValueError("cache_in_archive")
        # Case-fold valid UTF-8 consistently with paths; retain arbitrary binary bytes.
        folded = body.decode("utf-8", "surrogateescape").casefold().encode("utf-8", "surrogateescape")
        if any(marker in folded for marker in markers):
            raise ValueError("private_marker_in_archive")
        members[name] = body

    if wheel:
        with zipfile.ZipFile(path) as archive:
            if len(archive.infolist()) > 1024:
                raise ValueError("archive_capacity")
            for member in archive.infolist():
                original_path = member_path(member.orig_filename, directory=member.is_dir())
                mode = member.external_attr >> 16
                if member.is_dir():
                    if stat.S_IFMT(mode) not in {0, stat.S_IFDIR}:
                        raise ValueError("nonregular_archive_member")
                    if member.file_size != 0 or archive.read(member) != b"":
                        raise ValueError("nonempty_archive_directory")
                    directories.add(str(original_path))
                    continue
                if stat.S_IFMT(mode) not in {0, stat.S_IFREG}:
                    raise ValueError("nonregular_archive_member")
                if member.file_size > 8 * 1024 * 1024:
                    raise ValueError("archive_capacity")
                add(member.filename, archive.read(member))
        metadata = [p.split("/")[0] for p in members if p.endswith(".dist-info/METADATA")]
        if len(metadata) != 1 or not metadata[0].startswith("decision_mesh-"):
            raise ValueError("wrong_distribution")
        info = metadata[0]
        if any(not p.startswith(("decision_mesh/", info + "/")) for p in members) or any(
            p not in {"decision_mesh", info} and not p.startswith(("decision_mesh/", info + "/"))
            for p in directories
        ):
            raise ValueError("unexpected_public_file")
        scripts = members.get(info + "/entry_points.txt", b"")
        for item in (
            b"decisionmesh = decision_mesh.cli:main",
            b"decisionmesh-capture = decision_mesh.adapters.codex:main",
        ):
            if item not in scripts:
                raise ValueError("missing_console_script")
        if not any(p.endswith("/licenses/LICENSE") for p in members):
            raise ValueError("missing_license")
        prefix = "decision_mesh/"
    else:
        with tarfile.open(path, "r:gz", tarinfo=_OriginalPathTarInfo) as archive:
            entries = archive.getmembers()
            if len(entries) > 1024:
                raise ValueError("archive_capacity")
            roots = set()
            for member in entries:
                for original in member.original_names:
                    member_path(original, directory=member.isdir())
                # PAX retains the original effective path even when tarfile trims
                # it before assigning TarInfo.path.
                if "path" in member.pax_headers:
                    member_path(member.pax_headers["path"], directory=member.isdir())
                parts = member_path(member.name, directory=member.isdir()).parts
                if not parts or not parts[0].startswith("decision_mesh-"):
                    raise ValueError("wrong_distribution")
                roots.add(parts[0])
                rel = "/".join(parts[1:])
                if member.isdir():
                    if member.size != 0:
                        raise ValueError("nonempty_archive_directory")
                    if rel not in {
                        "",
                        "src",
                        "src/decision_mesh",
                        "docs",
                        "docs/public",
                    } and not rel.startswith(("src/decision_mesh/", "docs/public/")):
                        raise ValueError("unexpected_public_file")
                    continue
                if not member.isfile() or member.size > 8 * 1024 * 1024:
                    raise ValueError("nonregular_archive_member")
                if not (
                    rel in PUBLIC_ROOT or rel.startswith(("src/decision_mesh/", "docs/public/"))
                ):
                    raise ValueError("unexpected_public_file")
                stream = archive.extractfile(member)
                if stream is None:
                    raise ValueError("missing_archive_member")
                add(rel, stream.read())
            if len(roots) != 1:
                raise ValueError("multiple_source_roots")
        prefix = "src/decision_mesh/"
        for required in ("pyproject.toml", "LICENSE", "README.md", "PKG-INFO"):
            if required not in members:
                raise ValueError("missing_source_metadata")
    if not all(prefix + p in members for p in REQUIRED_RESOURCES):
        raise ValueError("missing_package_resource")
    return {
        "artifact": path.name,
        "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
        "file_count": len(members),
        "allowlist_passed": True,
        "private_marker_scan_passed": True,
        "resources_present": True,
        "members": {p: hashlib.sha256(b).hexdigest() for p, b in sorted(members.items())},
    }


def smoke_install(wheel: Path, work: Path) -> dict:
    if not work.is_absolute() or work.exists() or work.is_symlink():
        raise ValueError("new_absolute_work_directory_required")
    work.mkdir(parents=True, exist_ok=False)
    envdir = work / "environment"
    venv.EnvBuilder(with_pip=True).create(envdir)
    scripts = envdir / ("Scripts" if os.name == "nt" else "bin")
    python = scripts / ("python.exe" if os.name == "nt" else "python")
    command = scripts / ("decisionmesh.exe" if os.name == "nt" else "decisionmesh")
    capture_command = scripts / (
        "decisionmesh-capture.exe" if os.name == "nt" else "decisionmesh-capture"
    )
    env = os.environ.copy()
    for key in ("PYTHONPATH", "PYTHONHOME", "PIP_INDEX_URL", "PIP_EXTRA_INDEX_URL"):
        env.pop(key, None)
    env["PIP_CONFIG_FILE"] = os.devnull
    env["PIP_DISABLE_PIP_VERSION_CHECK"] = "1"
    env["PATH"] = str(scripts) + os.pathsep + env.get("PATH", "")

    def run(args, data=None, timeout=180):
        process = subprocess.run(
            [str(x) for x in args],
            input=data,
            text=True,
            capture_output=True,
            check=False,
            cwd=work,
            env=env,
            timeout=timeout,
        )
        if process.returncode != 0:
            raise RuntimeError("installed_command_failed")
        return process.stdout

    run([python, "-m", "pip", "install", "--index-url", "https://pypi.org/simple", wheel])
    run([python, "-m", "pip", "check"])
    if not command.is_file() or not capture_command.is_file():
        raise ValueError("installed_scripts_missing")
    probe = """import importlib.metadata as m, importlib.resources as r, json, pathlib, sys
import decision_mesh
base=pathlib.Path(sys.prefix).resolve()
assert pathlib.Path(decision_mesh.__file__).resolve().is_relative_to(base)
root=r.files('decision_mesh')
required=json.loads(sys.argv[1])
assert all(root.joinpath(p).is_file() for p in required)
print(json.dumps({'version':m.version('decision-mesh'),'python':sys.version.split()[0],
                 'resources':True,'import_from_environment':True}))
"""
    installed = json.loads(run([python, "-I", "-c", probe, json.dumps(sorted(REQUIRED_RESOURCES))]))
    if "producer" not in run([command, "--help"]):
        raise ValueError("installed_help_failed")
    absent = work / "never-created"
    doctor = json.loads(run([command, "doctor", "--data-dir", absent]))
    if absent.exists() or doctor.get("native_support") == "qualified":
        raise ValueError("doctor_side_effect_or_unsupported_claim")
    data = work / "user-data"
    enrolled = json.loads(run([command, "producer", "enroll", "--data-dir", data]))
    if enrolled.get("runtime_started") is not False:
        raise ValueError("unexpected_runtime_start")
    sample_probe = "from importlib.resources import files; print(files('decision_mesh').joinpath('resources/decision-mesh/example-request.json').read_text())"
    sample = run([python, "-I", "-c", sample_probe])
    receipt = json.loads(run([command, "producer", "create", "--data-dir", data], sample))
    if not receipt.get("accepted_to_spool") or receipt.get("ingested") is not False:
        raise ValueError("incorrect_spool_receipt")

    verification_results = []
    try:
        for _ in range(2):
            checked = json.loads(
                run(
                    [command, "setup", "--verify-local", "--local-only", "--data-dir", data],
                    timeout=40,
                )
            )
            if not (
                checked.get("ok") is True
                and checked.get("environment_verified") is True
                and checked.get("local_capture_verified") is True
                and checked.get("scope") == "local_runtime"
                and checked.get("native_qualification") == "unverified"
                and checked.get("policy_ready") is False
                and checked.get("reconciliation_required") is True
            ):
                raise ValueError("installed_local_verification_failed")
            verification_results.append(checked)
        saved = json.loads(run([command, "setup", "--status", "--data-dir", data]))
        if not saved.get("local_capture_verified") or not saved.get("environment_verified"):
            raise ValueError("installed_setup_stage_missing")
    finally:
        run([command, "stop", "--data-dir", data], timeout=20)
        deadline = time.monotonic() + 10
        while (data / "runtime.json").exists() and time.monotonic() < deadline:
            time.sleep(0.1)
        if (data / "runtime.json").exists():
            raise ValueError("installed_runtime_did_not_stop")

    def snapshot():
        return {
            str(p.relative_to(data)): hashlib.sha256(p.read_bytes()).hexdigest()
            for p in data.rglob("*")
            if p.is_file()
        }

    before = snapshot()
    run([python, "-m", "pip", "install", "--force-reinstall", "--no-deps", wheel])
    if snapshot() != before:
        raise ValueError("reinstall_changed_user_data")
    run([command, "--help"])
    deps = json.loads(run([python, "-m", "pip", "list", "--format=json"]))
    run([python, "-m", "pip", "uninstall", "--yes", "decision-mesh"])
    gone = run(
        [
            python,
            "-I",
            "-c",
            "import importlib.util; print(importlib.util.find_spec('decision_mesh') is None)",
        ]
    ).strip()
    if gone != "True" or command.exists() or capture_command.exists() or snapshot() != before:
        raise ValueError("uninstall_ownership_failed")
    return {
        "installed": installed,
        "dependency_check": "passed",
        "doctor_readonly": True,
        "producer_spool_smoke": True,
        "installed_runtime_local_verification_twice": verification_results,
        "installed_runtime_stopped": True,
        "launch_environment": "candidate virtual environment Scripts prepended to PATH",
        "same_version_reinstall_preserved_data": True,
        "uninstall_preserved_data_and_removed_package": True,
        "dependencies_before_uninstall": deps,
        "limits": [
            "same-version reinstall is not an upgrade compatibility test",
            "no native host, browser, credentials or external notification exercised",
        ],
    }


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("artifact", type=Path)
    parser.add_argument("--install-work", type=Path)
    parser.add_argument("--report", type=Path, required=True)
    args = parser.parse_args()
    result = inspect_archive(args.artifact.resolve())
    if args.install_work:
        if args.artifact.suffix != ".whl":
            parser.error("install smoke requires a wheel")
        result["install_smoke"] = smoke_install(args.artifact.resolve(), args.install_work)
    args.report.parent.mkdir(parents=True, exist_ok=True)
    args.report.write_text(json.dumps(result, indent=2), encoding="utf-8")
    print(json.dumps({k: v for k, v in result.items() if k not in {"members", "install_smoke"}}))
    if "install_smoke" in result:
        print(
            "Clean install, readonly diagnostics, local reporting, reinstall and uninstall checks passed."
        )


if __name__ == "__main__":
    main()
