"""Pack, inspect and exercise only the explicitly allowed public bootstrap files."""

from __future__ import annotations

import base64
import hashlib
import json
import os
import shutil
import subprocess
import tarfile
import tempfile
from pathlib import Path, PurePosixPath, PureWindowsPath

ROOT = Path(__file__).resolve().parents[2]
PACKAGE = ROOT / "npm/decisionmesh"
ALLOWED = frozenset(
    {
        "package.json",
        "index.js",
        "index.d.ts",
        "bin/schema.js",
        "schemas/event.schema.json",
        "README.md",
        "LICENSE",
    }
)
PRIVATE_MARKERS = (
    b"c:/users/",
    b"c:\\users",
    b"begin private key",
    b"npm_",
    b"ghp_",
    b".superpowers",
    b"council-findings",
)


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


def check_private_content(body: bytes, markers: tuple[bytes, ...]) -> None:
    # Case-fold valid UTF-8 consistently with paths; retain arbitrary binary bytes.
    folded = body.decode("utf-8", "surrogateescape").casefold().encode("utf-8", "surrogateescape")
    if any(marker in folded for marker in markers):
        raise RuntimeError("private_marker_in_artifact")


def run(args: list[str], cwd: Path) -> subprocess.CompletedProcess:
    result = subprocess.run(args, cwd=cwd, capture_output=True, timeout=90, check=False)
    if result.returncode:
        raise RuntimeError("bootstrap_check_command_failed")
    return result


def main() -> None:
    markers = private_markers()
    npm = shutil.which("npm.cmd") or shutil.which("npm")
    node = shutil.which("node")
    if not npm or not node:
        raise RuntimeError("node_and_npm_required")
    dist = ROOT / "dist/npm"
    dist.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="decisionmesh-package-check-") as temp:
        sandbox = Path(temp)
        cache = sandbox / "cache"
        common = ["--ignore-scripts", "--cache", str(cache), "--logs-max=0"]
        packed = json.loads(
            run([npm, "pack", "--json", "--pack-destination", str(dist), *common], PACKAGE).stdout
        )
        if len(packed) != 1:
            raise RuntimeError("unexpected_pack_count")
        artifact = dist / packed[0]["filename"]
        data = artifact.read_bytes()
        integrity = "sha512-" + base64.b64encode(hashlib.sha512(data).digest()).decode("ascii")
        if integrity != packed[0]["integrity"]:
            raise RuntimeError("pack_integrity_mismatch")
        rows = []
        with tarfile.open(artifact, "r:gz") as archive:
            members = archive.getmembers()
            names = [m.name.removeprefix("package/") for m in members]
            if len(names) != len(set(names)) or set(names) != ALLOWED:
                raise RuntimeError("public_allowlist_mismatch")
            for member in members:
                if not member.isfile() or not member.name.startswith("package/"):
                    raise RuntimeError("non_regular_archive_member")
                relative = member.name[len("package/") :]
                body = archive.extractfile(member).read()
                if body != (PACKAGE / relative).read_bytes():
                    raise RuntimeError("packed_content_mismatch")
                check_private_content(body, markers)
                rows.append(
                    {
                        "path": relative,
                        "bytes": len(body),
                        "sha256": hashlib.sha256(body).hexdigest(),
                    }
                )
        consumer = sandbox / "consumer"
        consumer.mkdir()
        (consumer / "package.json").write_text('{"private":true,"type":"module"}', encoding="utf-8")
        run(
            [
                npm,
                "install",
                str(artifact),
                "--no-audit",
                "--no-fund",
                "--package-lock=false",
                *common,
            ],
            consumer,
        )
        result = run(
            [
                node,
                "--input-type=module",
                "-e",
                "import {getEventSchemaText} from 'decisionmesh'; process.stdout.write(getEventSchemaText());",
            ],
            consumer,
        )
        expected = (PACKAGE / "schemas/event.schema.json").read_bytes()
        if result.stdout != expected or result.stderr:
            raise RuntimeError("installed_schema_api_mismatch")
        shim_result = run(
            [npm, "exec", "--offline", *common, "--", "decisionmesh-schema", "event"], consumer
        )
        if shim_result.stdout != expected or shim_result.stderr:
            raise RuntimeError("installed_bin_shim_mismatch")
        cli = consumer / "node_modules/decisionmesh/bin/schema.js"
        if run([node, str(cli), "event"], consumer).stdout != expected:
            raise RuntimeError("installed_cli_mismatch")
        metadata = json.loads((PACKAGE / "package.json").read_text(encoding="utf-8"))
        if (
            run([node, str(cli), "--version"], consumer).stdout.decode().strip()
            != metadata["version"]
        ):
            raise RuntimeError("installed_version_mismatch")
        run(
            [
                npm,
                "uninstall",
                "decisionmesh",
                "--no-audit",
                "--no-fund",
                "--package-lock=false",
                *common,
            ],
            consumer,
        )
        if (consumer / "node_modules/decisionmesh").exists():
            raise RuntimeError("uninstall_left_package")
        result = {
            "name": metadata["name"],
            "version": metadata["version"],
            "artifact": artifact.name,
            "sha256": hashlib.sha256(data).hexdigest(),
            "integrity": integrity,
            "files": sorted(rows, key=lambda row: row["path"]),
            "checks": [
                "exact-seven-file-allowlist",
                "no-links-or-private-markers",
                "all-packed-bytes-match-source",
                "clean-installed-api-and-cli",
                "installed-npm-bin-shim",
                "exact-integer-precision",
                "uninstall",
            ],
            "node": run([node, "--version"], consumer).stdout.decode().strip(),
            "published": False,
        }
        (dist / "bootstrap-check.json").write_text(
            json.dumps(result, indent=2) + "\n", encoding="utf-8"
        )
        print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
