"""Run the current planner against the sample scenarios and print the local
score. These samples are only for development; the graded scenarios are hidden.

    python3 samples/run_local.py
"""

import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
APP = os.path.dirname(HERE)
sys.path.insert(0, APP)

from assistant import harness
from assistant import planner


def main():
    with open(os.path.join(HERE, "scenarios.json")) as f:
        scenarios = json.load(f)
    reward, rows = harness.grade(planner.plan, scenarios)
    for row in rows:
        print(row)
    print("LOCAL REWARD (samples only):", round(reward, 4))


if __name__ == "__main__":
    main()
