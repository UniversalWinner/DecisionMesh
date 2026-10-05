# Contributing

Decision Mesh is an alpha Python project using Pydantic, SQLite, Flask/Waitress and an optional Telegram channel. Keep public behavior grounded in actual evidence: observing a gate, recording a request, provider acceptance, and agent execution are separate facts.

Use the [source repository](https://github.com/UniversalWinner/DecisionMesh) and Python 3.12 or newer; current Windows verification uses Python 3.13.14. Create a virtual environment:

```sh
python -m venv .venv
```

Activate it with your platform's normal command, then install and run the source checks:

```sh
python -m pip install -e ".[dev]"
python -m pytest -ra
python -m ruff check src tests tools/release
```

Use temporary directories, synthetic credentials and injected providers for tests. Never send a real message, write actual credentials or change another person's startup entries as a side effect of a test. Tests on one environment do not qualify another supported platform.

Node.js 22 or newer is required for the executable npm bootstrap tests; npm is also required for its package check. Those execution tests skip if Node is absent. Optional browser tests in `tests/test_web_browser.py` require the Python Playwright package and its matching Chromium installation. The tests never install either; they skip if Playwright is absent and fail if an installed Playwright cannot launch Chromium. To prepare and run that optional group explicitly:

```sh
python -m pip install playwright
python -m playwright install chromium
python -m pytest tests/test_web_browser.py -ra
```

Review every skip reported by `-ra`. A green suite with skipped installed-wheel, platform, Node, or browser checks does not qualify those paths or establish a production-ready release. Native-host lifecycle and external-channel qualification require their own evidence.

## Build and inspect a fresh candidate

A clean source checkout has no historical `dist/` artifacts. From its root, with the virtual environment active:

```sh
python -m pip install build
python -m build --outdir dist/candidate
python tools/release/check_python_distribution.py dist/candidate/decision_mesh-0.1.0a1-py3-none-any.whl --report dist/candidate/wheel-check.json
python tools/release/check_python_distribution.py dist/candidate/decision_mesh-0.1.0a1.tar.gz --report dist/candidate/source-check.json
```

These checks inspect archive scope, paths, resource inclusion and private markers; they do not install or publish the package. Both Python and npm checkers derive private path markers from the current checkout and user profile. For additional private context, set `DECISIONMESH_PRIVATE_PATHS` to a JSON array of absolute private directory paths in the environment before running either checker. These entries supplement the defaults and fixed secret markers; an empty array does not disable them. Invalid configuration fails with a fixed error, and marker values are not included in reports. This targeted scan complements review of the public file allowlist; it is not a complete secret detector.

The Windows installed-launch regression normally skips in a clean checkout because no historical wheel is present. Supply the freshly checked wheel explicitly so the test exercises its exact bytes:

```sh
python -c "import os, pathlib, subprocess, sys; os.environ['DECISIONMESH_TEST_WHEEL'] = str(pathlib.Path('dist/candidate/decision_mesh-0.1.0a1-py3-none-any.whl').resolve()); sys.exit(subprocess.call([sys.executable, '-m', 'pytest', 'tests/test_cli.py::test_rt4_installed_full_path_launch_ignores_path_selection', '-ra']))"
```

That test creates temporary installed environments while reusing the development environment's third-party dependencies. It is an installed-launch regression, not a clean-machine dependency or upgrade qualification. On other operating systems it remains skipped. The checker also supports a separate disposable install/reinstall/uninstall smoke check:

```sh
python tools/release/check_python_distribution.py dist/candidate/decision_mesh-0.1.0a1-py3-none-any.whl --install-work <absolute-new-work-directory> --report dist/candidate/install-check.json
```

Replace the placeholder with a new absolute directory. The smoke check installs dependencies from PyPI, exercises a local-only runtime, stops it, and retains its work directory for evidence. It does not qualify native capture, external notifications, browser behavior or version upgrades. Neither route publishes a package.

Preserve stable request identity, capture-time privacy choices, explicit activation, ambiguous-send accounting, bounded reads and exact ownership. Add targeted regressions for behavioral defects. Keep formatting and refactors scoped to the change. Changes to runtime, credentials, external sends, local authentication or OS integration require independent review and suitable integration checks before release.

## Public source and distribution scope

The public source repository includes reviewed synthetic tests and fixtures under `tests/`, public documentation, and release checks under `tools/release/`. Keep those synthetic cases reproducible and free of real developer identities, credentials, private paths or captured user data. Live/private fixtures, raw host probes, internal research, workspace records and qualification evidence remain excluded from public source.

Distribution payloads have narrower allowlists: Python wheels contain the application and packaged resources; source distributions also contain the selected public documentation and build metadata. Neither Python distribution includes the source test suite or release tooling. The npm bootstrap lives under `npm/decisionmesh`; its schema is generated from Python contracts by `tools/release/export_npm_schema.py`. Its package checker uses a disposable consumer and an exact seven-file allowlist:

```sh
python tools/release/check_npm_bootstrap.py
```

That command packs and locally installs/checks/uninstalls the bootstrap without publishing. Review generated artifacts separately from the public source repository.
