"""Public bootstrap checks: structural export fidelity and no runtime authority."""

import importlib.util
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
PKG = ROOT / "npm/decisionmesh"
NODE = shutil.which("node")
spec = importlib.util.spec_from_file_location(
    "npm_release_check", ROOT / "tools/release/check_npm_bootstrap.py"
)
check = importlib.util.module_from_spec(spec)
spec.loader.exec_module(check)


@pytest.mark.parametrize("private_root", ["checkout", "profile", "configured"])
@pytest.mark.parametrize("separator", ["/", "\\", "\\\\"])
def test_private_paths_are_derived_and_additive(monkeypatch, private_root, separator):
    roots = {
        "checkout": "Q:/SyntheticCheckout",
        "profile": "Q:/SyntheticProfile",
        "configured": "Q:/SyntheticPrivateContext",
    }
    monkeypatch.setattr(check, "ROOT", Path(roots["checkout"]))
    monkeypatch.setattr(check.Path, "home", lambda: Path(roots["profile"]))
    monkeypatch.setenv("DECISIONMESH_PRIVATE_PATHS", json.dumps([roots["configured"]]))
    body = (roots[private_root].upper() + "/private-state").replace("/", separator).encode()
    with pytest.raises(RuntimeError, match="^private_marker_in_artifact$"):
        check.check_private_content(body, check.private_markers())


@pytest.mark.parametrize("private_root", ["checkout", "profile", "configured"])
@pytest.mark.parametrize("spelling", ["original", "lower", "upper", "backslash", "escaped"])
def test_unicode_private_paths_use_consistent_case_matching(monkeypatch, private_root, spelling):
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
    with pytest.raises(RuntimeError, match="^private_marker_in_artifact$"):
        check.check_private_content(
            (value + "/private-state").encode("utf-8"), check.private_markers()
        )


@pytest.mark.parametrize("kind", ["unicode_path", "ascii_path", "secret", "harmless"])
def test_unicode_matching_preserves_arbitrary_binary_scanning(monkeypatch, kind):
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
    if kind == "harmless":
        check.check_private_content(body, check.private_markers())
    else:
        with pytest.raises(RuntimeError, match="^private_marker_in_artifact$"):
            check.check_private_content(body, check.private_markers())


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


def test_unencodable_private_path_cli_error_omits_private_values():
    root = "R:/private-sentinel/" + chr(0xD800)
    env = os.environ.copy()
    env["DECISIONMESH_PRIVATE_PATHS"] = json.dumps([root])
    result = subprocess.run(
        [sys.executable, str(ROOT / "tools/release/check_npm_bootstrap.py")],
        env=env,
        capture_output=True,
        timeout=15,
        check=False,
    )
    output = result.stdout + result.stderr
    assert result.returncode != 0
    assert b"invalid_private_path_configuration" in output
    assert b"private-sentinel" not in output and b"UnicodeEncodeError" not in output


@pytest.mark.parametrize(
    "body", [b"BEGIN PRIVATE KEY", b"npm_synthetic", b"ghp_synthetic", b".superpowers", b"council-findings"]
)
def test_private_path_configuration_preserves_fixed_markers(monkeypatch, body):
    monkeypatch.setenv("DECISIONMESH_PRIVATE_PATHS", "[]")
    with pytest.raises(RuntimeError, match="^private_marker_in_artifact$"):
        check.check_private_content(body, check.private_markers())


@pytest.mark.parametrize("root", ["/srv/synthetic-private", "//synthetic-server/private-share"])
def test_configured_posix_and_unc_private_paths_are_rejected(monkeypatch, root):
    monkeypatch.setenv("DECISIONMESH_PRIVATE_PATHS", json.dumps([root]))
    with pytest.raises(RuntimeError, match="^private_marker_in_artifact$"):
        check.check_private_content((root + "/private-state").encode(), check.private_markers())


@pytest.mark.parametrize("value", ["not-json", "{}", '[1]', '[""]', '["relative"]', '["Q:/"]'])
def test_invalid_private_paths_fail_closed_without_disclosing_values(monkeypatch, value):
    monkeypatch.setenv("DECISIONMESH_PRIVATE_PATHS", value)
    with pytest.raises(ValueError, match="^invalid_private_path_configuration$"):
        check.private_markers()


def test_unrelated_windows_example_path_is_admitted(monkeypatch):
    monkeypatch.setenv("DECISIONMESH_PRIVATE_PATHS", '["Q:/SyntheticPrivateContext"]')
    check.check_private_content(b"Q:/PublicExample/harmless.txt", check.private_markers())


def test_bundled_schema_matches_authoritative_export():
    spec = importlib.util.spec_from_file_location(
        "npm_schema_export", ROOT / "tools/release/export_npm_schema.py"
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    assert (PKG / "schemas/event.schema.json").read_bytes() == module.schema_bytes()


def test_all_schema_references_are_bundled():
    schema = json.loads((PKG / "schemas/event.schema.json").read_text())

    def visit(value):
        if isinstance(value, dict):
            if "$ref" in value:
                ref = value["$ref"]
                assert ref.startswith("#/")
                target = schema
                for part in ref[2:].split("/"):
                    target = target[part.replace("~1", "/").replace("~0", "~")]
            for child in value.values():
                visit(child)
        elif isinstance(value, list):
            for child in value:
                visit(child)

    visit(schema)


def test_manifest_has_no_dependencies_or_execution_hooks():
    package = json.loads((PKG / "package.json").read_text())
    assert not package.get("dependencies")
    assert not package.get("scripts")
    assert package["publishConfig"]["tag"] == "bootstrap"
    assert package["license"] == "MIT"


@pytest.mark.skipif(NODE is None, reason="Node is required for npm bootstrap execution")
def test_cli_export_and_invalid_arguments_are_redacted(tmp_path):
    cli = PKG / "bin/schema.js"
    result = subprocess.run(
        [NODE, str(cli), "event"], cwd=tmp_path, capture_output=True, timeout=15, check=False
    )
    assert result.returncode == 0
    assert result.stdout == (PKG / "schemas/event.schema.json").read_bytes()
    assert result.stderr == b""
    bad = subprocess.run(
        [NODE, str(cli), "private-do-not-repeat-value"],
        cwd=tmp_path,
        capture_output=True,
        timeout=15,
        check=False,
    )
    assert bad.returncode == 2
    assert b"private-do-not-repeat-value" not in bad.stdout + bad.stderr
    assert not list(tmp_path.iterdir())


@pytest.mark.skipif(NODE is None, reason="Node is required for npm bootstrap execution")
def test_text_api_preserves_exact_schema_including_large_integer_limits(tmp_path):
    code = (
        "import { getEventSchemaText } from "
        + json.dumps((PKG / "index.js").as_uri())
        + "; process.stdout.write(getEventSchemaText());"
    )
    result = subprocess.run(
        [NODE, "--input-type=module", "-e", code],
        cwd=tmp_path,
        capture_output=True,
        timeout=15,
        check=False,
    )
    assert result.returncode == 0
    assert result.stdout == (PKG / "schemas/event.schema.json").read_bytes()
    assert b"9223372036854775807" in result.stdout
    assert not list(tmp_path.iterdir())
