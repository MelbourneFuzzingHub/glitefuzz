import argparse
import importlib
import os
import sys
import time
import uuid

from Scheduler.RandomDiskScheduler import RandomDiskScheduler
from Scheduler.RandomMemScheduler import RandomMemScheduler


FUZZERS = [
    "AdamicAdar", "BCC", "HarmonicCentrality", "JaccardSimilarity",
    "MAXFV", "MaxMatching", "MST", "SCC", "STPL",
]
FEEDBACK_MODES = [
    "regular", "coverage", "combination", "branch", "branchhit", "none",
]


def get_fuzzer_class(fuzzer_name):
    module = importlib.import_module(f"Fuzzer.{fuzzer_name}Fuzzer")
    return getattr(module, f"{fuzzer_name}Fuzzer")


def run_fuzzer(fuzzer, output_mode):
    if output_mode == "console":
        fuzzer.run()
        return

    log_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "Log")
    os.makedirs(log_dir, exist_ok=True)
    log_path = os.path.join(
        log_dir,
        f"{fuzzer.__class__.__name__.lower()}_{uuid.uuid4().hex[:6]}_log.txt",
    )
    original_stdout, original_stderr = sys.stdout, sys.stderr
    try:
        with open(log_path, "w", buffering=1, encoding="utf-8") as stream:
            sys.stdout = stream
            sys.stderr = stream
            fuzzer.run()
    finally:
        sys.stdout = original_stdout
        sys.stderr = original_stderr
    print(f"Log saved to: {log_path}")


def main():
    parser = argparse.ArgumentParser(description="Run a GLiteFuzz fuzzer")
    parser.add_argument("fuzzer", choices=FUZZERS)
    parser.add_argument("--num_iterations", type=int, default=60)
    parser.add_argument("--use_multiple_graphs", action="store_true")
    parser.add_argument(
        "--feedback_check_type", choices=FEEDBACK_MODES, default="regular")
    parser.add_argument("--output", choices=["file", "console"],
                        default="console")
    parser.add_argument("--scheduler", choices=["mem", "disk"], default="mem")
    parser.add_argument("--folder", default="graphs_folder")
    parser.add_argument("--timeout", type=float, default=20)
    args = parser.parse_args()

    scheduler = (
        RandomMemScheduler(time.time())
        if args.scheduler == "mem"
        else RandomDiskScheduler(args.folder)
    )
    fuzzer = get_fuzzer_class(args.fuzzer)(
        num_iterations=args.num_iterations,
        use_multiple_graphs=args.use_multiple_graphs,
        feedback_check_type=args.feedback_check_type,
        scheduler=scheduler,
        timeout_duration=args.timeout,
    )
    run_fuzzer(fuzzer, args.output)


if __name__ == "__main__":
    main()
