# -*- mode: python ; coding: utf-8 -*-
"""PyInstaller spec for the gh-audit standalone executable."""

from pathlib import Path

ROOT = Path(SPECPATH)
SRC = ROOT / "src"
TEMPLATES = SRC / "gh_audit" / "templates"

a = Analysis(
    [str(SRC / "gh_audit" / "cli" / "app.py")],
    pathex=[str(SRC)],
    binaries=[],
    datas=[
        (str(TEMPLATES), "gh_audit/templates"),
    ],
    hiddenimports=[
        "click",
        "pydantic",
        "pydantic._internal",
        "pydantic_settings",
        "structlog",
        "httpx",
        "posthog",
        "jinja2",
        "openpyxl",
        "yaml",
        "rich",
        "typer",
        "shellingham",
        "shellingham.nt",
        "shellingham.posix",
        "jwt",
        "cryptography",
    ],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[
        "pytest",
        "mypy",
        "ruff",
        "respx",
    ],
    noarchive=False,
)

pyz = PYZ(a.pure, a.zipped_data)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.datas,
    [],
    name="gh-audit",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=True,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
)
