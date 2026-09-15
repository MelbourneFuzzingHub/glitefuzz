import csv
import inspect
import os
import tempfile
import time
import unittest

import networkx as nx

from BaseFuzzer import BaseFuzzer
from Feedback.FeedbackTools import (
    BranchHitTracker,
    FeedbackTools,
    get_count_bucket,
)
from Fuzzer.HarmonicCentralityFuzzer import HarmonicCentralityFuzzer
from Fuzzer.MSTFuzzer import MSTFuzzer
from Fuzzer.MaxMatchingFuzzer import MaxMatchingFuzzer
from Fuzzer.STPLFuzzer import STPLFuzzer
from Scheduler.RandomDiskScheduler import RandomDiskScheduler
from Scheduler.RandomMemScheduler import RandomMemScheduler
from Utils.FileUtils import save_bug


def _inner_trace_target():
    value = 1
    return value


def _outer_trace_target():
    before = 1
    _inner_trace_target()
    after = 2
    return before + after


class DummyFuzzer(BaseFuzzer):
    def get_corpus_name(self):
        return "dummy"

    def executor(self, graph):
        return graph.number_of_nodes()

    def get_tester(self):
        return None

    def create_single_graph(self):
        return [nx.Graph([(0, 1)])]

    def create_multiple_graphs(self):
        return self.create_single_graph()

    def process_test_results(self, graph, tester, first_occurrence_times,
                             total_bug_counts, timestamp, parent_id=None,
                             ops=None):
        return None


class FeedbackTest(unittest.TestCase):
    def test_hit_count_buckets(self):
        expected = {
            0: 0, 1: 1, 2: 2, 3: 3, 4: 4, 7: 4, 8: 5,
            15: 5, 16: 6, 31: 6, 32: 7, 127: 7, 128: 8,
        }
        for count, bucket in expected.items():
            with self.subTest(count=count):
                self.assertEqual(get_count_bucket(count), bucket)

    def test_branch_tracker_does_not_cross_stack_frames(self):
        tracker = BranchHitTracker([os.path.dirname(__file__)])
        tracker.start()
        try:
            _outer_trace_target()
        finally:
            tracker.stop()

        inner_lines, inner_start = inspect.getsourcelines(_inner_trace_target)
        outer_lines, outer_start = inspect.getsourcelines(_outer_trace_target)
        inner_range = range(inner_start, inner_start + len(inner_lines))
        outer_range = range(outer_start, outer_start + len(outer_lines))
        for _, (source, target) in tracker.counts:
            crosses_frames = (
                (source in inner_range and target in outer_range)
                or (source in outer_range and target in inner_range)
            )
            self.assertFalse(crosses_frames)

    def test_combination_always_updates_both_signals(self):
        fuzzer = DummyFuzzer()
        calls = []
        fuzzer.regular_feedback_check = lambda graph: calls.append("output") or True
        fuzzer.coverage_feedback_check = lambda graph: calls.append("coverage") or False
        self.assertTrue(fuzzer.combination_feedback_check(nx.Graph()))
        self.assertEqual(calls, ["output", "coverage"])

    def test_coverage_and_branchhit_novelty(self):
        graph = nx.path_graph(5)

        def algorithm(value):
            return list(nx.bfs_edges(value, 0))

        line_feedback = FeedbackTools()
        self.assertTrue(
            line_feedback.is_new_and_interesting_coverage_updated(
                graph, algorithm))
        self.assertFalse(
            line_feedback.is_new_and_interesting_coverage_updated(
                graph, algorithm))

        branchhit_feedback = FeedbackTools()
        self.assertTrue(
            branchhit_feedback.is_new_branch_hitcount_triggered(
                graph, algorithm))
        self.assertFalse(
            branchhit_feedback.is_new_branch_hitcount_triggered(
                graph, algorithm))


class CorpusTest(unittest.TestCase):
    def test_exact_graph_key_ignores_insertion_order(self):
        first = nx.Graph()
        first.add_node(1, color="red")
        first.add_edge(1, 2, weight=3)
        second = nx.Graph()
        second.add_edge(2, 1, weight=3)
        second.nodes[1]["color"] = "red"
        self.assertEqual(
            DummyFuzzer.canonical_graph_key(first),
            DummyFuzzer.canonical_graph_key(second),
        )
        second[1][2]["weight"] = 4
        self.assertNotEqual(
            DummyFuzzer.canonical_graph_key(first),
            DummyFuzzer.canonical_graph_key(second),
        )

    def test_duplicate_graph_is_not_retained(self):
        scheduler = RandomMemScheduler(time.time())
        fuzzer = DummyFuzzer(scheduler=scheduler)
        graph = nx.Graph([(0, 1)])
        self.assertEqual(fuzzer.retain_graph(graph, 0, ["seed"]), 1)
        self.assertIsNone(fuzzer.retain_graph(graph.copy(), 1, ["copy"]))
        self.assertEqual(scheduler.graph_counter, 1)

    def test_disk_scheduler_records_lineage(self):
        with tempfile.TemporaryDirectory() as directory:
            scheduler = RandomDiskScheduler(directory)
            graph_id = scheduler.add_to_corpus(
                nx.path_graph(3), parent_id=7, ops=["add node", "trim/graph"])
            self.assertEqual(graph_id, 1)
            files = os.listdir(directory)
            self.assertEqual(
                files,
                ["id_000001,src_000007,op_add_node+trim_graph.pkl"],
            )
            graph, selected_id = scheduler.get_graph()
            self.assertEqual(selected_id, 1)
            self.assertEqual(list(graph.edges()), [(0, 1), (1, 2)])

    def test_bug_manifest_records_lineage(self):
        with tempfile.TemporaryDirectory() as directory:
            self.assertTrue(save_bug(
                nx.Graph([(0, 1)]), 1.25, 4, ["add_edge"], directory,
                "different results"))
            with open(os.path.join(directory, "bugs.csv"),
                      newline="", encoding="utf-8") as stream:
                row = next(csv.DictReader(stream))
            self.assertEqual(row["parent_id"], "4")
            self.assertEqual(row["ops"], "add_edge")
            self.assertTrue(os.path.exists(os.path.join(directory, row["filename"])))


class AlgorithmFeedbackTest(unittest.TestCase):
    def test_corrected_feedback_projectors(self):
        matching = {0: 1, 1: 0, 2: 3, 3: 2}
        self.assertEqual(
            MaxMatchingFuzzer.matching_cardinality_interesting_check(
                None, matching),
            2,
        )
        self.assertEqual(
            STPLFuzzer.shortest_path_interesting_check(float("inf")),
            ("SPF_NO_PATH",),
        )
        self.assertAlmostEqual(
            HarmonicCentralityFuzzer.centrality_min_gap(
                {0: 0.4, 1: 0.1, 2: 0.7}),
            0.3,
        )
        tree = nx.Graph()
        tree.add_weighted_edges_from([(0, 1, 2), (1, 2, 2)])
        self.assertEqual(
            MSTFuzzer.mst_weight_interesting_check(None, tree),
            (3, "3_2^2"),
        )


if __name__ == "__main__":
    unittest.main()
