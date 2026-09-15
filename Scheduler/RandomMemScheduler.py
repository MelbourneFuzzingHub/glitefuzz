import random
import time


class RandomMemScheduler:
    def __init__(self, start_time):
        self.corpus_memory = []
        self.start_time = start_time
        self.graph_counter = 0

    def add_to_corpus(self, graphs, parent_id=None, ops=None):
        if not isinstance(graphs, list):
            graphs = [graphs]

        last_id = None
        for graph in graphs:
            self.graph_counter += 1
            last_id = self.graph_counter
            self.corpus_memory.append({
                "timestamp": time.time() - self.start_time,
                "graph": graph,
                "id": last_id,
                "parent_id": parent_id,
                "ops": list(ops or []),
            })
        return last_id

    def get_graph(self):
        if not self.corpus_memory:
            raise ValueError("No graphs available in memory")
        entry = random.choice(self.corpus_memory)
        return entry["graph"], entry["id"]

    def iterate_graphs(self):
        yield from self.corpus_memory

    def close_current_file(self):
        return None
