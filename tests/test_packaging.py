"""Archive admission checks for public distribution privacy and required resources."""

import gzip
import importlib.util
import io
import json
import os
import subprocess
import sys
import tarfile
import zipfile
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location(
    "release_check", ROOT / "tools/release/check_python_distribution.py"
)
check = importlib.util.module_from_spec(spec)
spec.loader.exec_module(check)


def wheel(path, extra=None, missing=None):
    info = "decision_mesh-0.1.0a1.dist-info"
    members = {
        info + "/METADATA": b"Name: decision-mesh\nVersion: 0.1.0a1\n",
        info + "/licenses/LICENSE": b"MIT",
        info + "/entry_points.txt": (
            b"[console_scripts]\ndecisionmesh = decision_mesh.cli:main\n"
            b"decisionmesh-capture = decision_mesh.adapters.codex:main\n"
        ),
        **{"decision_mesh/" + x: b"synthetic" for x in check.REQUIRED_RESOURCES},
    }
    if missing:
        members.pop(missing)
    if extra:
        members.update(extra)
    with zipfile.ZipFile(path, "w") as archive:
        for name, body in members.items():
            archive.writestr(name, body)


def test_required_resources_and_scripts_are_admitted(tmp_path):
    path = tmp_path / "candidate.whl"
    wheel(path)
    result = check.inspect_archive(path)
    assert result["resources_present"] and result["allowlist_passed"]
    assert result["file_count"] == len(check.REQUIRED_RESOURCES) + 3


@pytest.mark.parametrize(
    "name,body",
    [
        ("../escaped.py", b"x"),
        ("decision_mesh/../escaped.py", b"x"),
        ("decision_mesh//double.py", b"x"),
        ("docs/research/private.md", b"x"),
        ("decision_mesh/__pycache__/x.pyc", b"x"),
        ("decision_mesh/key.pem", b"-----BEGIN PRIVATE KEY-----"),
    ],
)
def test_rejects_scope_escape_caches_and_private_content(tmp_path, name, body):
    path = tmp_path / "candidate.whl"
    wheel(path, {name: body})
    with pytest.raises(ValueError):
        check.inspect_archive(path)


@pytest.mark.parametrize("archive_kind", ["wheel", "source"])
@pytest.mark.parametrize("private_root", ["checkout", "profile", "configured"])
@pytest.mark.parametrize("separator", ["/", "\\", "\\\\"])
def test_private_paths_are_derived_and_additive(
    tmp_path, monkeypatch, archive_kind, private_root, separator
):
    roots = {
        "checkout": "Q:/SyntheticCheckout",
        "profile": "Q:/SyntheticProfile",
        "configured": "Q:/SyntheticPrivateContext",
    }
    monkeypatch.setattr(check, "ROOT", Path(roots["checkout"]), raising=False)
    monkeypatch.setattr(check.Path, "home", lambda: Path(roots["profile"]))
    monkeypatch.setenv("DECISIONMESH_PRIVATE_PATHS", json.dumps([roots["configured"]]))
    body = (roots[private_root].upper() + "/private-state").replace("/", separator).encode()
    path = tmp_path / ("candidate.whl" if archive_kind == "wheel" else "candidate.tar.gz")
    if archive_kind == "wheel":
        wheel(path, {"decision_mesh/accidental.txt": body})
    else:
        source_archive(path, extra_file={"src/decision_mesh/accidental.txt": body})
    with pytest.raises(ValueError, match="^private_marker_in_archive$"):
        check.inspect_archive(path)


@pytest.mark.parametrize("archive_kind", ["wheel", "source"])
@pytest.mark.parametrize("private_root", ["checkout", "profile", "configured"])
@pytest.mark.parametrize("spelling", ["original", "lower", "upper", "backslash", "escaped"])
def test_unicode_private_paths_use_consistent_case_matching(
    tmp_path, monkeypatch, archive_kind, private_root, spelling
):
    roots = {
        "checkout": "R:/SyntheticCheckout/Évidence/Straße",
        "profile": "R:/SyntheticProfile/Évidence/Straße",
        "configured": "R:/SyntheticContext/Évidence/Straße",
    }
    monkeypatch.setattr(check, "ROOT", Path(roots["checkout"]))
    monkeypatch.setattr(check.Path, "home", lambda: Path(roots["profile"]))
    monkeypatch.setenv("DECISIONMESH_PRIVATE_PATHS", json.dumps([roots["configured"]]))
    value = roots[private_root]
    value = {
        "original": value,
        "lower": value.lower(),
        "upper": value.upper(),
        "backslash": value.replace("/", "\\"),
        "escaped": value.replace("/", "\\\\"),
    }[spelling]
    body = (value + "/private-state").encode("utf-8")
    path = tmp_path / ("candidate.whl" if archive_kind == "wheel" else "candidate.tar.gz")
    if archive_kind == "wheel":
        wheel(path, {"decision_mesh/accidental.txt": body})
    else:
        source_archive(path, extra_file={"src/decision_mesh/accidental.txt": body})
    with pytest.raises(ValueError, match="^private_marker_in_archive$"):
        check.inspect_archive(path)


@pytest.mark.parametrize("kind", ["unicode_path", "ascii_path", "secret", "harmless"])
def test_unicode_matching_preserves_arbitrary_binary_scanning(tmp_path, monkeypatch, kind):
    root = "R:/SyntheticContext/Évidence"
    ascii_root = "R:/SyntheticAsciiContext"
    monkeypatch.setenv("DECISIONMESH_PRIVATE_PATHS", json.dumps([root, ascii_root]))
    payload = {
        "unicode_path": (root + "/private-state").encode("utf-8"),
        "ascii_path": (ascii_root.upper() + "/private-state").encode("utf-8"),
        "secret": b"-----BEGIN PRIVATE KEY-----",
        "harmless": b"R:/PublicExample/harmless.txt",
    }[kind]
    body = b"\xff\x80\xc3" + payload + b"\xfe\x80"
    path = tmp_path / "candidate.whl"
    wheel(path, {"decision_mesh/binary.dat": body})
    if kind == "harmless":
        assert check.inspect_archive(path)["private_marker_scan_passed"]
    else:
        with pytest.raises(ValueError, match="^private_marker_in_archive$"):
            check.inspect_archive(path)


@pytest.mark.parametrize("private_root", ["checkout", "profile", "configured"])
def test_unencodable_private_paths_have_fixed_redacted_errors(monkeypatch, private_root):
    root = "R:/private-sentinel/" + chr(0xD800)
    monkeypatch.setenv("DECISIONMESH_PRIVATE_PATHS", "[]")
    if private_root == "configured":
        monkeypatch.setenv("DECISIONMESH_PRIVATE_PATHS", json.dumps([root]))
    elif private_root == "checkout":
        monkeypatch.setattr(check, "ROOT", Path(root))
    else:
        monkeypatch.setattr(check.Path, "home", lambda: Path(root))
    with pytest.raises(ValueError, match="^invalid_private_path_configuration$") as caught:
        check.private_markers()
    assert type(caught.value) is ValueError
    assert caught.value.__suppress_context__


def test_unencodable_private_path_cli_error_omits_private_values(tmp_path):
    root = "R:/private-sentinel/" + chr(0xD800)
    env = os.environ.copy()
    env["DECISIONMESH_PRIVATE_PATHS"] = json.dumps([root])
    report = tmp_path / "unused-report.json"
    result = subprocess.run(
        [
            sys.executable,
            str(ROOT / "tools/release/check_python_distribution.py"),
            str(tmp_path / "unused.whl"),
            "--report",
            str(report),
        ],
        env=env,
        capture_output=True,
        timeout=15,
        check=False,
    )
    output = result.stdout + result.stderr
    assert result.returncode != 0
    assert b"invalid_private_path_configuration" in output
    assert b"private-sentinel" not in output and b"UnicodeEncodeError" not in output
    assert not report.exists()


def test_private_path_configuration_does_not_replace_secret_markers(tmp_path, monkeypatch):
    monkeypatch.setenv("DECISIONMESH_PRIVATE_PATHS", "[]")
    path = tmp_path / "candidate.whl"
    wheel(path, {"decision_mesh/key.pem": b"-----BEGIN PRIVATE KEY-----"})
    with pytest.raises(ValueError, match="^private_marker_in_archive$"):
        check.inspect_archive(path)


@pytest.mark.parametrize("root", ["/srv/synthetic-private", "//synthetic-server/private-share"])
def test_configured_posix_and_unc_private_paths_are_rejected(tmp_path, monkeypatch, root):
    monkeypatch.setenv("DECISIONMESH_PRIVATE_PATHS", json.dumps([root]))
    path = tmp_path / "candidate.whl"
    wheel(path, {"decision_mesh/accidental.txt": (root + "/private-state").encode()})
    with pytest.raises(ValueError, match="^private_marker_in_archive$"):
        check.inspect_archive(path)


@pytest.mark.parametrize("value", ["not-json", "{}", '[1]', '[""]', '["relative"]', '["Q:/"]'])
def test_invalid_private_paths_fail_closed_without_disclosing_values(tmp_path, monkeypatch, value):
    monkeypatch.setenv("DECISIONMESH_PRIVATE_PATHS", value)
    path = tmp_path / "candidate.whl"
    wheel(path)
    with pytest.raises(ValueError, match="^invalid_private_path_configuration$"):
        check.inspect_archive(path)


def test_unrelated_windows_example_path_is_admitted(tmp_path, monkeypatch):
    monkeypatch.setenv("DECISIONMESH_PRIVATE_PATHS", '["Q:/SyntheticPrivateContext"]')
    path = tmp_path / "candidate.whl"
    wheel(path, {"decision_mesh/example.txt": b"Q:/PublicExample/harmless.txt"})
    assert check.inspect_archive(path)["private_marker_scan_passed"]


def test_missing_skill_blocks_artifact(tmp_path):
    path = tmp_path / "candidate.whl"
    wheel(path, missing="decision_mesh/resources/decision-mesh/SKILL.md")
    with pytest.raises(ValueError, match="missing_package_resource"):
        check.inspect_archive(path)


def test_symlink_is_rejected_even_when_spelled_like_directory(tmp_path):
    path = tmp_path / "candidate.whl"
    wheel(path)
    with zipfile.ZipFile(path, "a") as archive:
        member = zipfile.ZipInfo("decision_mesh/link/")
        member.create_system = 3
        member.external_attr = 0o120777 << 16
        archive.writestr(member, b"outside")
    with pytest.raises(ValueError, match="nonregular_archive_member"):
        check.inspect_archive(path)


def test_source_archive_rejects_internal_report(tmp_path):
    path = tmp_path / "candidate.tar.gz"
    with tarfile.open(path, "w:gz") as archive:
        data = b"internal"
        member = tarfile.TarInfo("decision_mesh-0.1.0a1/docs/implementation/report.md")
        member.size = len(data)
        archive.addfile(member, io.BytesIO(data))
    with pytest.raises(ValueError, match="unexpected_public_file"):
        check.inspect_archive(path)


def source_archive(
    path,
    transform=lambda name: name,
    extra_directory=None,
    pax_path=None,
    *,
    extra_file=None,
    archive_format=tarfile.PAX_FORMAT,
):
    root = "decision_mesh-0.1.0a1"
    members = {
        "pyproject.toml": b"[project]\nname='decision-mesh'\n",
        "LICENSE": b"MIT",
        "README.md": b"Candidate",
        "PKG-INFO": b"Name: decision-mesh\nVersion: 0.1.0a1\n",
        **{"src/decision_mesh/" + x: b"synthetic" for x in check.REQUIRED_RESOURCES},
    }
    if extra_file:
        members.update(extra_file)
    with tarfile.open(path, "w:gz", format=archive_format) as archive:
        for relative, body in members.items():
            member = tarfile.TarInfo(transform(root + "/" + relative))
            member.size = len(body)
            archive.addfile(member, io.BytesIO(body))
        if extra_directory is not None:
            member = tarfile.TarInfo(extra_directory)
            member.type = tarfile.DIRTYPE
            if pax_path is not None:
                member.pax_headers = {"path": pax_path}
            archive.addfile(member)


def test_canonical_source_archive_is_admitted(tmp_path):
    path = tmp_path / "candidate.tar.gz"
    source_archive(path)
    assert check.inspect_archive(path)["allowlist_passed"]


@pytest.mark.parametrize(
    "transform",
    [
        lambda name: name.replace("/", "//", 1),
        lambda name: name.replace("/", "/./", 1),
        lambda name: name.replace("decision_mesh-0.1.0a1", "decision_mesh-0.1.0a1\\..\\..", 1),
        lambda name: name.replace("decision_mesh-0.1.0a1", "decision_mesh-0.1.0a1:C:", 1),
    ],
)
def test_source_archive_validates_original_path_before_stripping_root(tmp_path, transform):
    path = tmp_path / "candidate.tar.gz"
    source_archive(path, transform)
    with pytest.raises(ValueError, match="unsafe_archive_path"):
        check.inspect_archive(path)


@pytest.mark.parametrize(
    "directory",
    [
        "decision_mesh-0.1.0a1/../outside",
        "decision_mesh-0.1.0a1//src",
        "decision_mesh-0.1.0a1:C:/src",
        "decision_mesh-0.1.0a1\\..\\../src",
    ],
)
def test_source_archive_validates_directory_headers_too(tmp_path, directory):
    path = tmp_path / "candidate.tar.gz"
    source_archive(path, extra_directory=directory)
    with pytest.raises(ValueError, match="unsafe_archive_path"):
        check.inspect_archive(path)


def test_wheel_rejects_noncanonical_directory_header(tmp_path):
    path = tmp_path / "candidate.whl"
    wheel(path)
    with zipfile.ZipFile(path, "a") as archive:
        member = zipfile.ZipInfo("decision_mesh/../outside/")
        member.create_system = 3
        member.external_attr = 0o40700 << 16
        archive.writestr(member, b"")
    with pytest.raises(ValueError, match="unsafe_archive_path"):
        check.inspect_archive(path)


@pytest.mark.parametrize(
    "directory",
    [
        "decision_mesh-0.1.0a1",
        "decision_mesh-0.1.0a1/src/decision_mesh/",
        "decision_mesh-0.1.0a1/src/",
        "decision_mesh-0.1.0a1/docs/",
        "decision_mesh-0.1.0a1/docs/public/",
        "decision_mesh-0.1.0a1/docs/public/tutorials/",
    ],
)
def test_canonical_source_directory_is_admitted(tmp_path, directory):
    path = tmp_path / "candidate.tar.gz"
    source_archive(path, extra_directory=directory)
    assert check.inspect_archive(path)["allowlist_passed"]


def test_canonical_wheel_directory_is_admitted(tmp_path):
    path = tmp_path / "candidate.whl"
    wheel(path)
    with zipfile.ZipFile(path, "a") as archive:
        archive.writestr("decision_mesh/", b"")
    assert check.inspect_archive(path)["allowlist_passed"]


@pytest.mark.parametrize(
    "original,replacement",
    [
        (b"decision_mesh/cli.py", b"decision_mesh\\cli.py"),
        (b"decision_mesh/cli.py", b"decision_mesh/c\x00i.py"),
        (b"decision_mesh/raw/dir/", b"decision_mesh\\raw/dir/"),
    ],
)
def test_rejects_raw_zip_names_before_reader_normalizes(tmp_path, original, replacement):
    path = tmp_path / "candidate.whl"
    wheel(path, {original.decode(): b""})
    raw = path.read_bytes()
    assert len(original) == len(replacement) and raw.count(original) == 2
    path.write_bytes(raw.replace(original, replacement))
    with pytest.raises(ValueError, match="unsafe_archive_path"):
        check.inspect_archive(path)


@pytest.mark.parametrize("suffix", ["//", "///"])
def test_rejects_raw_tar_directory_before_reader_trims(tmp_path, suffix):
    path = tmp_path / "candidate.tar.gz"
    original = "decision_mesh-0.1.0a1/raw/"
    source_archive(path, extra_directory=original)
    raw = bytearray(gzip.decompress(path.read_bytes()))
    offset = raw.find(original.encode())
    assert offset >= 0 and offset % 512 == 0
    header = bytearray(raw[offset : offset + 512])
    header[:100] = ("decision_mesh-0.1.0a1/raw" + suffix).encode().ljust(100, b"\0")
    header[148:156] = b" " * 8
    header[148:156] = f"{sum(header):06o}\0 ".encode()
    raw[offset : offset + 512] = header
    path.write_bytes(gzip.compress(raw))
    with pytest.raises(ValueError, match="unsafe_archive_path"):
        check.inspect_archive(path)


@pytest.mark.parametrize("suffix,accepted", [("/", True), ("//", False), ("///", False)])
def test_pax_directory_path_preserves_canonical_rule(tmp_path, suffix, accepted):
    path = tmp_path / "candidate.tar.gz"
    name = "decision_mesh-0.1.0a1/src/decision_mesh/extended" + suffix
    source_archive(
        path, extra_directory="decision_mesh-0.1.0a1/src/decision_mesh/placeholder", pax_path=name
    )
    assert ("path=" + name + "\n").encode() in gzip.decompress(path.read_bytes())
    if accepted:
        assert check.inspect_archive(path)["allowlist_passed"]
    else:
        with pytest.raises(ValueError, match="unsafe_archive_path"):
            check.inspect_archive(path)


@pytest.mark.parametrize("archive_format", [tarfile.PAX_FORMAT, tarfile.GNU_FORMAT])
@pytest.mark.parametrize("cut", ["slash", "dot"])
def test_round3_canonical_extended_tar_name_ignores_truncated_fallback(
    tmp_path, archive_format, cut
):
    path = tmp_path / "candidate.tar.gz"
    prefix = "decision_mesh-0.1.0a1/src/decision_mesh/"
    full = (
        (prefix + "a" * (99 - len(prefix)) + "/leaf.py")
        if cut == "slash"
        else (prefix + "a" * (98 - len(prefix)) + "/.leaf.py")
    )
    assert len(full) > 100 and full[99] == ("/" if cut == "slash" else ".")
    relative = full.split("/", 1)[1]
    source_archive(
        path, extra_file={relative: b"canonical long path"}, archive_format=archive_format
    )
    raw = gzip.decompress(path.read_bytes())
    assert any(
        raw[offset : offset + 100] == full[:100].encode() for offset in range(0, len(raw), 512)
    )
    assert (
        (b"path=" + full.encode() + b"\n") in raw
        if archive_format == tarfile.PAX_FORMAT
        else full.encode() + b"\0" in raw
    )
    assert relative in check.inspect_archive(path)["members"]


@pytest.mark.parametrize("name", ["decision_mesh/notes/", "private-notes/"])
@pytest.mark.parametrize("mode", [0o40700, 0o600])
def test_round3_wheel_directory_payload_is_rejected(tmp_path, name, mode):
    path = tmp_path / "candidate.whl"
    wheel(path)
    with zipfile.ZipFile(path, "a") as archive:
        member = zipfile.ZipInfo(name)
        member.create_system = 3
        member.external_attr = mode << 16
        archive.writestr(member, b"synthetic directory payload")
    with zipfile.ZipFile(path) as archive:
        member = archive.getinfo(name)
        assert member.is_dir() and archive.read(member) == b"synthetic directory payload"
    with pytest.raises(ValueError):
        check.inspect_archive(path)


@pytest.mark.parametrize(
    "directory", ["private-notes/", "docs/public/", "decision_mesh-9.dist-info/"]
)
def test_round3_wheel_out_of_scope_directory_is_rejected(tmp_path, directory):
    path = tmp_path / "candidate.whl"
    wheel(path, {directory: b""})
    with pytest.raises(ValueError, match="unexpected_public_file"):
        check.inspect_archive(path)


@pytest.mark.parametrize(
    "directory", ["docs/implementation/", "src/other/", "private-notes/", "README.md/"]
)
def test_round3_source_out_of_scope_directory_is_rejected(tmp_path, directory):
    path = tmp_path / "candidate.tar.gz"
    source_archive(path, extra_directory="decision_mesh-0.1.0a1/" + directory)
    with pytest.raises(ValueError, match="unexpected_public_file"):
        check.inspect_archive(path)


@pytest.mark.parametrize(
    "directory",
    [
        "decision_mesh/",
        "decision_mesh/nested/",
        "decision_mesh-0.1.0a1.dist-info/",
        "decision_mesh-0.1.0a1.dist-info/licenses/",
    ],
)
def test_round3_empty_compressed_wheel_directory_is_admitted(tmp_path, directory):
    path = tmp_path / "candidate.whl"
    wheel(path)
    with zipfile.ZipFile(path, "a", compression=zipfile.ZIP_DEFLATED) as archive:
        archive.writestr(directory, b"")
    with zipfile.ZipFile(path) as archive:
        member = archive.getinfo(directory)
        assert member.file_size == 0 and member.compress_size > 0
        assert archive.read(member) == b""
    assert check.inspect_archive(path)["allowlist_passed"]


@pytest.mark.parametrize("archive_format", [tarfile.PAX_FORMAT, tarfile.GNU_FORMAT])
@pytest.mark.parametrize("suffix", ["/", "//", "///"])
def test_round3_extended_tar_directory_keeps_effective_original_spelling(
    tmp_path, archive_format, suffix
):
    path = tmp_path / "candidate.tar.gz"
    full = "decision_mesh-0.1.0a1/src/decision_mesh/" + "a" * 80 + suffix
    source_archive(path, extra_directory=full, archive_format=archive_format)
    raw = gzip.decompress(path.read_bytes())
    assert (
        (b"path=" + full.encode() + b"\n") in raw
        if archive_format == tarfile.PAX_FORMAT
        else full.encode() + b"\0" in raw
    )
    if suffix == "/":
        assert check.inspect_archive(path)["allowlist_passed"]
    else:
        with pytest.raises(ValueError, match="unsafe_archive_path"):
            check.inspect_archive(path)


@pytest.mark.parametrize("archive_format", [tarfile.PAX_FORMAT, tarfile.GNU_FORMAT])
@pytest.mark.parametrize("ending", ["//file.py", "/../file.py"])
def test_round3_extended_tar_file_rejects_effective_noncanonical_path(
    tmp_path, archive_format, ending
):
    path = tmp_path / "candidate.tar.gz"
    relative = "src/decision_mesh/" + "a" * 90 + ending
    source_archive(path, extra_file={relative: b"synthetic"}, archive_format=archive_format)
    full = "decision_mesh-0.1.0a1/" + relative
    raw = gzip.decompress(path.read_bytes())
    assert (
        (b"path=" + full.encode() + b"\n") in raw
        if archive_format == tarfile.PAX_FORMAT
        else full.encode() + b"\0" in raw
    )
    with pytest.raises(ValueError, match="unsafe_archive_path"):
        check.inspect_archive(path)


def test_round3_tar_directory_with_declared_payload_is_rejected(tmp_path):
    path = tmp_path / "candidate.tar.gz"
    name = "decision_mesh-0.1.0a1/src/decision_mesh/empty/"
    source_archive(path, extra_directory=name)
    raw = bytearray(gzip.decompress(path.read_bytes()))
    offset = raw.find(name.encode())
    assert offset >= 0 and offset % 512 == 0
    header = bytearray(raw[offset : offset + 512])
    header[124:136] = b"00000000001\0"
    header[148:156] = b" " * 8
    header[148:156] = f"{sum(header):06o}\0 ".encode()
    raw[offset : offset + 512] = header
    path.write_bytes(gzip.compress(raw))
    with tarfile.open(path, "r:gz") as archive:
        member = archive.getmembers()[-1]
        assert member.isdir() and member.size == 1
    with pytest.raises(ValueError, match="nonempty_archive_directory"):
        check.inspect_archive(path)
