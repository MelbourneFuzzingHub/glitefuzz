import os
import pickle
import random
import re
import time


class RandomDiskScheduler:
    """Store each corpus graph separately with AFL-like lineage metadata."""

    _ID_PATTERN = re.compile(r"^id_(\d+),")

    def __init__(self, folder_name):
        self.folder_name = os.path.abspath(folder_name)
        os.makedirs(self.folder_name, exist_ok=True)
        self.start_time = time.time()
        self._files = {}
        for filename in os.listdir(self.folder_name):
            match = self._ID_PATTERN.match(filename)
            if match and filename.endswith(".pkl"):
                self._files[int(match.group(1))] = filename
        self.graph_counter = max(self._files, default=0)

    @staticmethod
    def _safe_operation(operation):
        safe = re.sub(r"[^A-Za-z0-9_.-]+", "_", str(operation))
        return safe.strip("_") or "unknown"

    def add_to_corpus(self, graphs, parent_id=None, ops=None):
        if not isinstance(graphs, list):
            graphs = [graphs]

        last_id = None
        for graph in graphs:
            self.graph_counter += 1
            last_id = self.graph_counter
            source = parent_id if parent_id is not None else 0
            operations = "+".join(
                self._safe_operation(operation) for operation in (ops or ["seed"])
            )
            filename = (
                f"id_{last_id:06},src_{source:06},op_{operations}.pkl")
            with open(os.path.join(self.folder_name, filename), "wb") as stream:
                pickle.dump(graph, stream)
            self._files[last_id] = filename
        return last_id

    def get_graph(self):
        if not self._files:
            raise ValueError("No graphs available on disk")
        graph_id = random.choice(tuple(self._files))
        path = os.path.join(self.folder_name, self._files[graph_id])
        with open(path, "rb") as stream:
            return pickle.load(stream), graph_id

    def iterate_graphs(self):
        for graph_id in sorted(self._files):
            filename = self._files[graph_id]
            with open(os.path.join(self.folder_name, filename), "rb") as stream:
                yield {
                    "graph": pickle.load(stream),
                    "id": graph_id,
                    "filename": filename,
                }

    def close_current_file(self):
        return None
