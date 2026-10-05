"""Read installed Windows launchers using their actual on-disk format."""

import json
from pathlib import Path

import pytest
from test_windows_setup import SID, Backend

from decision_mesh import diagnostics
from decision_mesh.capture import atomic_write_owner_only
from decision_mesh.runtime_control import RuntimePaths
from decision_mesh.windows_setup import WindowsIntegration


@pytest.fixture
def owned_installation(tmp_path, monkeypatch):
    # Isolate launcher diagnostics from unrelated runtime lock creation.
    monkeypatch.setattr(diagnostics, "active_metadata", lambda _paths: None)
    backend = Backend()
    console = tmp_path / "installed programs" / "decisionmesh.exe"
    console.parent.mkdir()
    console.write_bytes(b"synthetic executable, never run")
    system = tmp_path / "Windows" / "System32"
    system.mkdir(parents=True)
    (system / "wscript.exe").write_bytes(b"synthetic executable, never run")
    programs = tmp_path / "Programs"
    programs.mkdir()
    options = {
        "data_dir": tmp_path / "data",
        "programs_dir": programs,
        "user_sid": SID,
        "backend": backend,
        "console_resolver": lambda: console,
        "windows_dir": system.parent,
    }
    return options, backend, console


def snapshot(root: Path):
    return {p.relative_to(root): p.read_bytes() for p in root.rglob("*") if p.is_file()}


@pytest.mark.parametrize("unicode_console", [False, True])
def test_valid_utf16_launchers_are_read_only_and_not_false_failures(
    owned_installation, monkeypatch, unicode_console
):
    options, backend, console = owned_installation
    if unicode_console:
        console = console.parent / "测试" / "decisionmesh.exe"
        console.parent.mkdir()
        console.write_bytes(b"synthetic executable, never run")
        options["console_resolver"] = lambda: console
    manager = WindowsIntegration(**options)
    manager.apply(manager.plan(autostart=True, shortcut=True))
    monkeypatch.setattr(diagnostics, "resolve_installed_console", lambda: console)
    before = snapshot(manager.data_dir)
    calls = list(backend.calls)
    result = diagnostics.doctor(RuntimePaths(manager.data_dir))
    assert result["windows_integration"] == "installed_paths_unverified"
    assert result["native_support"] == "unverified"
    assert snapshot(manager.data_dir) == before and backend.calls == calls
    assert str(console) not in json.dumps(result)
    assert str(manager.data_dir) not in json.dumps(result)


@pytest.mark.parametrize(
    "content,expected",
    [
        ("modified synthetic launcher".encode("utf-16"), "stale_installed_paths"),
        (b"\xff\xfe\x00", "manifest_failed"),
    ],
)
def test_invalid_launcher_stays_redacted_and_is_never_repaired_by_doctor(
    owned_installation, monkeypatch, content, expected
):
    options, backend, console = owned_installation
    manager = WindowsIntegration(**options)
    manager.apply(manager.plan(autostart=True))
    atomic_write_owner_only(manager.data_dir / "launch-run.vbs", content)
    monkeypatch.setattr(diagnostics, "resolve_installed_console", lambda: console)
    before = snapshot(manager.data_dir)
    calls = list(backend.calls)
    result = diagnostics.doctor(RuntimePaths(manager.data_dir))
    assert result["windows_integration"] == expected
    assert snapshot(manager.data_dir) == before and backend.calls == calls
    assert "modified synthetic launcher" not in json.dumps(result)
    assert str(console) not in json.dumps(result)
