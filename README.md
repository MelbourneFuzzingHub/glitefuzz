# GLiteFuzz

GLiteFuzz is a lightweight differential fuzzer for graph algorithms. It mutates
NetworkX graphs, compares multiple implementations, and retains inputs using
algorithm-output or coverage-based feedback.

## Setup

GLiteFuzz targets Ubuntu 22.04 and Python 3.10.

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

## Run

```bash
python3 main.py SCC --num_iterations 100 \
  --feedback_check_type branchhit \
  --scheduler disk --folder graphs_folder
```

Available fuzzers:

```text
AdamicAdar  BCC  HarmonicCentrality  JaccardSimilarity  MAXFV
MaxMatching  MST  SCC  STPL
```

Feedback modes:

- `regular`: algorithm-specific output
- `coverage`: new NetworkX lines reported by coverage.py
- `combination`: regular and line-coverage feedback, both updated per input
- `branch`: new NetworkX arcs reported by coverage.py
- `branchhit`: new AFL-style hit-count buckets for transitions
- `none`: no mutation feedback

