import os
import sys
import time
from collections import Counter
from multiprocessing import Lock

import coverage
import networkx as nx


def get_count_bucket(count):
    """Return the AFL-style bucket for an execution count."""
    if count <= 0:
        return 0
    if count <= 3:
        return count
    if count <= 7:
        return 4
    if count <= 15:
        return 5
    if count <= 31:
        return 6
    if count <= 127:
        return 7
    return 8


def get_executed_lines(cov):
    executed_lines = set()
    for filename in cov.get_data().measured_files():
        for line in cov.get_data().lines(filename) or ():
            executed_lines.add((filename, line))
    return executed_lines


def get_executed_branches(cov):
    executed_branches = set()
    for filename in cov.get_data().measured_files():
        for arc in cov.get_data().arcs(filename) or ():
            executed_branches.add((filename, arc))
    return executed_branches


class BranchHitTracker:
    """Count Python line transitions while keeping state per stack frame."""

    def __init__(self, filter_paths):
        self.filter_paths = tuple(os.path.abspath(path) for path in filter_paths)
        self.counts = Counter()
        self._previous_lines = {}

    def _allowed(self, filename):
        filename = os.path.abspath(filename)
        return any(
            filename == path or filename.startswith(path + os.sep)
            for path in self.filter_paths
        )

    def trace(self, frame, event, arg):
        frame_id = id(frame)
        filename = frame.f_code.co_filename

        if event == "line" and self._allowed(filename):
            line = frame.f_lineno
            previous = self._previous_lines.get(frame_id)
            if previous is not None:
                self.counts[(filename, (previous, line))] += 1
            self._previous_lines[frame_id] = line
        elif event == "return":
            self._previous_lines.pop(frame_id, None)

        return self.trace

    def start(self):
        sys.settrace(self.trace)

    def stop(self):
        sys.settrace(None)
        self._previous_lines.clear()


class FeedbackTools:
    def __init__(self, start_time=None, line_counts=None, lock=None):
        self.observed_outputs = set()
        self.networkx_exceptions = set()
        self.other_exceptions = set()
        self.exception_graphs = {}
        self.line_counts = line_counts
        self.total_lines = set()
        self.start_time = start_time or time.time()
        self.observed_executed_lines = set()
        self.observed_branches = set()
        self.observed_branch_hit_counts = {}
        self.lock = lock or Lock()
        self.target_paths = [nx.__path__[0]]

    def _record_exception(self, graph, error):
        message = f"{type(error).__name__}: {error}"
        destination = (
            self.networkx_exceptions
            if isinstance(error, nx.NetworkXException)
            else self.other_exceptions
        )
        if message not in destination:
            destination.add(message)
            self.exception_graphs[graph] = message
            return True
        return False

    def is_new_and_interesting(self, graph, algorithm, check_func):
        try:
            key = check_func(algorithm(graph))
            if key not in self.observed_outputs:
                self.observed_outputs.add(key)
                return True
        except Exception as error:
            return self._record_exception(graph, error)
        return False

    def _coverage(self, branch=False):
        return coverage.Coverage(
            source=self.target_paths,
            branch=branch,
            data_file=None,
        )

    def is_new_and_interesting_coverage_updated(self, graph, algorithm):
        """Retain an input when it executes a previously unseen target line."""
        with self.lock:
            cov = self._coverage()
            cov.start()
            try:
                algorithm(graph)
            except Exception as error:
                self._record_exception(graph, error)
            finally:
                cov.stop()

            current_lines = get_executed_lines(cov)
            new_lines = current_lines - self.observed_executed_lines
            if new_lines:
                self.observed_executed_lines.update(new_lines)
                print(
                    f"New lines executed: {len(new_lines)}, "
                    f"Time: {time.time() - self.start_time:.4f}"
                )
                return True
            return False

    def is_new_branch_triggered(self, graph, algorithm):
        """Retain an input when coverage.py observes a new target arc."""
        with self.lock:
            cov = self._coverage(branch=True)
            cov.start()
            try:
                algorithm(graph)
            except Exception as error:
                self._record_exception(graph, error)
            finally:
                cov.stop()

            current_branches = get_executed_branches(cov)
            new_branches = current_branches - self.observed_branches
            if new_branches:
                self.observed_branches.update(new_branches)
                print(
                    f"New branches executed: {len(new_branches)}, "
                    f"Time: {time.time() - self.start_time:.4f}"
                )
                return True
            return False

    def is_new_branch_hitcount_triggered(self, graph, algorithm):
        """Retain an input when a target arc reaches a new hit-count bucket."""
        with self.lock:
            tracker = BranchHitTracker(self.target_paths)
            tracker.start()
            try:
                algorithm(graph)
            except Exception as error:
                self._record_exception(graph, error)
            finally:
                tracker.stop()

            new_details = []
            for key, count in tracker.counts.items():
                bucket = get_count_bucket(count)
                observed = self.observed_branch_hit_counts.setdefault(key, set())
                if bucket not in observed:
                    observed.add(bucket)
                    filename, arc = key
                    new_details.append(
                        f"{os.path.basename(filename)}:{arc[0]}->{arc[1]} "
                        f"(bucket {bucket})"
                    )

            if new_details:
                details = ", ".join(new_details[:5])
                if len(new_details) > 5:
                    details += f" and {len(new_details) - 5} more"
                print(
                    f"New branch-hit buckets: {details}, "
                    f"Time: {time.time() - self.start_time:.4f}"
                )
                return True
            return False
