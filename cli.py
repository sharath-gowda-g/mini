"""Simple CLI to run project tasks: capture, predict, train.

Usage examples:
  python cli.py --capture
  python cli.py --predict
  python cli.py --train

The commands run the corresponding scripts in this repository using the
current Python interpreter. Outputs are streamed to the console and simple
colored status messages are shown.
"""
from __future__ import annotations

import argparse
import os
import subprocess
import sys
import signal
from termcolor import colored


PROJECT_ROOT = os.path.dirname(__file__)


def run_script(script_name: str) -> int:
    """Run a Python script from the project root and stream output.

    Returns the process exit code.
    """
    script_path = os.path.join(PROJECT_ROOT, script_name)
    if not os.path.exists(script_path):
        print(colored(f"Script not found: {script_path}", "red"))
        return 2

    cmd = [sys.executable, script_path]
    print(colored(f"Running: {cmd}", "cyan"))

    # Start process and stream its stdout/stderr
    try:
        proc = subprocess.Popen(cmd, cwd=PROJECT_ROOT)

        # Forward signals from parent to child on POSIX; on Windows this is no-op
        try:
            proc.wait()
        except KeyboardInterrupt:
            print(colored("Interrupted by user. Terminating child process...", "yellow"))
            try:
                proc.send_signal(signal.SIGINT)
            except Exception:
                proc.terminate()
            proc.wait()

        return proc.returncode if proc.returncode is not None else 1
    except FileNotFoundError:
        print(colored("Python executable not found.", "red"))
        return 3
    except Exception as e:
        print(colored(f"Failed to run script: {e}", "red"))
        return 4


def cmd_capture(args: argparse.Namespace) -> int:
    print(colored("Starting DNS capture (requires Admin/Npcap). Press Ctrl+C to stop.", "green"))
    return run_script("capture.py")


def cmd_predict(args: argparse.Namespace) -> int:
    print(colored("Running offline prediction using best_dns_model.pkl...", "green"))
    return run_script("predict.py")


def cmd_train(args: argparse.Namespace) -> int:
    print(colored("Training models and selecting the best model (may take time)...", "green"))
    return run_script("train_best.py")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="DNS tunneling project helper CLI")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--capture", help="Run live DNS capture (capture.py)", action="store_true")
    group.add_argument("--predict", help="Run prediction on `dns_log.csv` (predict.py)", action="store_true")
    group.add_argument("--train", help="Train multiple models and save best (train_best.py)", action="store_true")

    args = parser.parse_args(argv)

    if args.capture:
        rc = cmd_capture(args)
    elif args.predict:
        rc = cmd_predict(args)
    elif args.train:
        rc = cmd_train(args)
    else:
        parser.print_help()
        return 2

    if rc == 0:
        print(colored("✅ Done.", "green"))
    else:
        print(colored(f"❌ Exited with code {rc}", "red"))
    return rc


if __name__ == "__main__":
    raise SystemExit(main())
