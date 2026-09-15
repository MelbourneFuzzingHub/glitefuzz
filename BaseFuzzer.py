import os
import signal
import threading
import time
from abc import ABC, abstractmethod

import networkx as nx

from Feedback.FeedbackTools import FeedbackTools
from Mutator.ExtendedMutator import ExtendedMutator
from Scheduler.RandomMemScheduler import RandomMemScheduler
from Utils.FileUtils import save_exception_graphs


class BaseFuzzer(ABC):
    """Shared mutation, feedback, deduplication, and corpus loop."""

    def __init__(self, num_iterations=60, use_multiple_graphs=False,
                 feedback_check_type="regular", scheduler=None,
                 timeout_duration=20):
        root = os.path.dirname(os.path.abspath(__file__))
        self.corpus_dir = os.path.join(root, "Corpus_Data")
        self.corpus_path = os.path.join(
            self.corpus_dir, self.get_corpus_name())
        os.makedirs(self.corpus_dir, exist_ok=True)

        self.num_iterations = num_iterations
        self.use_multiple_graphs = use_multiple_graphs
        self.feedback_check_type = feedback_check_type
        self.start_time = time.time()
        self.feedback_tool = FeedbackTools(start_time=self.start_time)
        self.total_bug_counts = {}
        self.count = 0
        self.scheduler = scheduler or RandomMemScheduler(self.start_time)
        self.num_graphs = self.scheduler.graph_counter
        self.timeout_duration = timeout_duration
        self.stop_fuzzing = threading.Event()
        self._corpus_keys = {
            self.canonical_graph_key(entry["graph"])
            for entry in self.scheduler.iterate_graphs()
        }
        self.bug_dir = (
            os.path.join(self.scheduler.folder_name, "bugs")
            if hasattr(self.scheduler, "folder_name")
            else None
        )

    def _timeout_handler(self, signum, frame):
        raise TimeoutError("Test execution exceeded the time limit")

    def process_test_results_with_timeout(
            self, graph, tester, first_occurrence_times, total_bug_counts,
            timestamp, parent_id=None, ops=None):
        previous_handler = signal.getsignal(signal.SIGALRM)
        signal.signal(signal.SIGALRM, self._timeout_handler)
        signal.setitimer(signal.ITIMER_REAL, self.timeout_duration)
        try:
            self.process_test_results(
                graph, tester, first_occurrence_times, total_bug_counts,
                timestamp, parent_id, ops)
            return True
        except TimeoutError:
            message = f"TimeoutError: exceeded {self.timeout_duration} seconds"
            if message not in self.feedback_tool.other_exceptions:
                self.feedback_tool.other_exceptions.add(message)
                self.feedback_tool.exception_graphs[graph] = message
            print(f"Timeout while processing graph at {timestamp:.4f} seconds.")
            return False
        except Exception as error:
            message = f"{type(error).__name__}: {error}"
            if message not in self.feedback_tool.other_exceptions:
                self.feedback_tool.other_exceptions.add(message)
                self.feedback_tool.exception_graphs[graph] = message
            print(f"Error while processing graph at {timestamp:.4f} seconds: {message}")
            return False
        finally:
            signal.setitimer(signal.ITIMER_REAL, 0)
            signal.signal(signal.SIGALRM, previous_handler)

    def regular_feedback_check(self, graph):
        return self.feedback_tool.is_new_and_interesting(
            graph, self.executor, self.interesting_check)

    def coverage_feedback_check(self, graph):
        return self.feedback_tool.is_new_and_interesting_coverage_updated(
            graph, self.executor)

    def combination_feedback_check(self, graph):
        # Update both histories even when the first signal is already novel.
        output_new = self.regular_feedback_check(graph)
        coverage_new = self.coverage_feedback_check(graph)
        return output_new or coverage_new

    def branch_coverage_feedback_check(self, graph):
        return self.feedback_tool.is_new_branch_triggered(graph, self.executor)

    def branch_hitcount_feedback_check(self, graph):
        return self.feedback_tool.is_new_branch_hitcount_triggered(
            graph, self.executor)

    def no_feedback_check(self, graph):
        return False

    def perform_feedback_checks(self, graph):
        feedback_methods = {
            "regular": self.regular_feedback_check,
            "coverage": self.coverage_feedback_check,
            "combination": self.combination_feedback_check,
            "branch": self.branch_coverage_feedback_check,
            "branchhit": self.branch_hitcount_feedback_check,
            "none": self.no_feedback_check,
        }
        try:
            method = feedback_methods[self.feedback_check_type]
        except KeyError as error:
            raise ValueError(
                f"Unknown feedback type: {self.feedback_check_type}") from error
        return method(graph)

    @staticmethod
    def _canonical_value(value):
        return type(value).__qualname__, repr(value)

    @classmethod
    def _canonical_attrs(cls, attrs):
        return tuple(sorted(
            (cls._canonical_value(key), cls._canonical_value(value))
            for key, value in attrs.items()
        ))

    @classmethod
    def canonical_graph_key(cls, graph):
        """Identify an exact labelled graph, including all attributes."""
        directed = graph.is_directed()
        multigraph = graph.is_multigraph()
        nodes = tuple(sorted(
            (cls._canonical_value(node), cls._canonical_attrs(attrs))
            for node, attrs in graph.nodes(data=True)
        ))

        def endpoints(source, target):
            pair = cls._canonical_value(source), cls._canonical_value(target)
            return pair if directed or pair[0] <= pair[1] else pair[::-1]

        if multigraph:
            edges = tuple(sorted(
                (*endpoints(source, target), cls._canonical_value(key),
                 cls._canonical_attrs(attrs))
                for source, target, key, attrs in graph.edges(
                    keys=True, data=True)
            ))
        else:
            edges = tuple(sorted(
                (*endpoints(source, target), cls._canonical_attrs(attrs))
                for source, target, attrs in graph.edges(data=True)
            ))

        return (
            type(graph).__qualname__, directed, multigraph,
            cls._canonical_attrs(graph.graph), nodes, edges,
        )

    def retain_graph(self, graph, parent_id=None, ops=None):
        if not isinstance(graph, nx.Graph) or graph.number_of_nodes() == 0:
            return None
        key = self.canonical_graph_key(graph)
        if key in self._corpus_keys:
            return None
        graph_id = self.scheduler.add_to_corpus(
            graph, parent_id=parent_id, ops=ops)
        self._corpus_keys.add(key)
        self.num_graphs += 1
        return graph_id

    def default_interesting_check(self, result):
        if isinstance(result, int):
            return result
        if isinstance(result, (list, set)):
            if all(isinstance(item, (set, frozenset)) for item in result):
                sizes = [len(component) for component in result]
                return max(sizes) if sizes else 0
            if all(isinstance(item, tuple) and len(item) == 3
                   for item in result):
                return max(result, key=lambda item: item[2])[2] if result else 0
        if isinstance(result, dict):
            return len(result)
        if isinstance(result, nx.Graph):
            total_weight = sum(
                data.get("weight", 1)
                for _, _, data in result.edges(data=True)
            )
            return total_weight, result.number_of_edges()
        raise ValueError(f"Unknown result type: {type(result)}")

    def interesting_check(self, result):
        if hasattr(self, "_user_interesting_check"):
            return self._user_interesting_check(result)
        return self.default_interesting_check(result)

    def set_interesting_check(self, function):
        self._user_interesting_check = function

    @abstractmethod
    def get_corpus_name(self):
        pass

    @abstractmethod
    def executor(self, graph):
        pass

    @abstractmethod
    def get_tester(self):
        pass

    @abstractmethod
    def create_single_graph(self):
        pass

    @abstractmethod
    def create_multiple_graphs(self):
        pass

    @abstractmethod
    def process_test_results(
            self, graph, tester, first_occurrence_times, total_bug_counts,
            timestamp, parent_id=None, ops=None):
        pass

    def signal_handler(self, sig, frame):
        self.stop_fuzzing.set()
        signal.signal(signal.SIGINT, signal.SIG_IGN)
        signal.signal(signal.SIGTERM, signal.SIG_IGN)
        raise KeyboardInterrupt

    def finalize_process(self):
        print("Finalizing process...")
        print(f"Executions: {self.count}")
        print(f"Corpus graphs: {self.num_graphs}")
        print(f"Time: {(time.time() - self.start_time) / 60:.3f} minutes")
        if self.feedback_tool.exception_graphs:
            save_exception_graphs(
                self.feedback_tool.exception_graphs, self.get_corpus_name())
        print("Total bugs found:")
        for category, total in self.total_bug_counts.items():
            print(f"{category}: {total}")

    def create_initial_graphs(self):
        if self.use_multiple_graphs:
            return self.create_multiple_graphs()
        return self.create_single_graph()

    def run(self):
        generated_graphs = self.create_initial_graphs()
        retained_seeds = []
        for graph in generated_graphs:
            graph_id = self.retain_graph(graph, parent_id=0, ops=["seed"])
            if graph_id is not None:
                retained_seeds.append((graph, graph_id))

        if not retained_seeds:
            raise ValueError("No valid, unique seed graphs were generated")
        print(f"Loaded {len(retained_seeds)} valid, unique seed graphs.")

        mutator = ExtendedMutator(self.scheduler)
        tester = self.get_tester()
        first_occurrence_times = {}

        signal.signal(signal.SIGINT, self.signal_handler)
        signal.signal(signal.SIGTERM, self.signal_handler)

        try:
            print("Performing initial feedback checks...")
            for graph, _ in retained_seeds:
                self.perform_feedback_checks(graph)

            while not self.stop_fuzzing.is_set():
                graph, graph_id = self.scheduler.get_graph()
                for _ in range(self.num_iterations):
                    if self.stop_fuzzing.is_set():
                        break
                    parent_id = graph_id
                    mutated_graph, ops = mutator.stacked_mutate(graph.copy())
                    self.count += 1
                    timestamp = time.time() - self.start_time
                    succeeded = self.process_test_results_with_timeout(
                        mutated_graph, tester, first_occurrence_times,
                        self.total_bug_counts, timestamp, parent_id, ops)
                    if succeeded and self.perform_feedback_checks(mutated_graph):
                        retained_id = self.retain_graph(
                            mutated_graph, parent_id=parent_id, ops=ops)
                        if retained_id is not None:
                            graph = mutated_graph
                            graph_id = retained_id
        except KeyboardInterrupt:
            print("Fuzzing interrupted.")
        finally:
            self.finalize_process()
