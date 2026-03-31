#!/usr/bin/env python3
"""Build gh-audit as a standalone PyInstaller binary."""

from __future__ import annotations

import platform
import subprocess
import sys
from pathlib import Path


def main() -> int:
    project_root = Path(__file__).resolve().parent.parent
    spec_file = project_root / "gh-audit.spec"

    if not spec_file.exists():
        print(f"[ERROR] Spec file not found: {spec_file}", file=sys.stderr)
        return 1

    exe_name = "gh-audit.exe" if platform.system() == "Windows" else "gh-audit"

    cmd = [
        sys.executable, "-m", "PyInstaller",
        str(spec_file),
        "--distpath", str(project_root / "dist"),
        "--workpath", str(project_root / "build"),
        "--clean",
    ]

    print(f"Building {exe_name}...")
    result = subprocess.run(cmd, cwd=str(project_root))
    if result.returncode != 0:
        print(f"[ERROR] Build failed with exit code {result.returncode}")
        return 1

    exe_path = project_root / "dist" / exe_name
    if not exe_path.exists():
        print(f"[ERROR] Expected binary not found: {exe_path}")
        return 1

    size_mb = exe_path.stat().st_size / 1_048_576
    print(f"[OK] Built {exe_path} ({size_mb:.1f} MB)")

    # Smoke test
    print("Running smoke test...")
    smoke = subprocess.run([str(exe_path), "--version"], capture_output=True, text=True)
    if smoke.returncode != 0:
        print(f"[ERROR] Smoke test failed: {smoke.stderr}")
        return 1
    print(f"[OK] {smoke.stdout.strip()}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
