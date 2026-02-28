#!/usr/bin/env python3
"""Watchdog: if main process crashes, start Plan B API."""

from __future__ import annotations

import argparse
import os
import subprocess
import sys
from pathlib import Path


def run_watchdog(target: Path, base_dir: Path, host: str, port: int) -> int:
    env = os.environ.copy()
    env["PYTHONPATH"] = f"{base_dir / 'src'}:{env.get('PYTHONPATH', '')}".rstrip(":")
    while True:
        proc = subprocess.Popen([sys.executable, str(target)], cwd=str(base_dir), env=env)
        exit_code = proc.wait()

        # If target exits cleanly, stop the watchdog.
        if exit_code == 0:
            return 0

        # On crash, start the Plan B API.
        subprocess.call([
            sys.executable,
            "-m",
            "archipel.plan_b.api",
            "--host",
            host,
            "--port",
            str(port),
            "--base-dir",
            str(base_dir),
        ], cwd=str(base_dir), env=env)

        # If API stops, retry running the main process.


def main() -> None:
    parser = argparse.ArgumentParser(description="Archipel Plan B watchdog")
    parser.add_argument("--target", required=True, help="Path to main Python script")
    parser.add_argument("--base-dir", default=str(Path.cwd()))
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=5055)
    args = parser.parse_args()

    target = Path(args.target).resolve()
    base_dir = Path(args.base_dir).resolve()
    raise SystemExit(run_watchdog(target, base_dir, args.host, args.port))


if __name__ == "__main__":
    main()
