# Document assistant workspace

- `assistant/planner.py` — the decision module you implement (`plan(context)`).
- `assistant/harness.py` — the reference environment: task rules, context,
  action executor and scorer, identical to what the grader uses.
- `samples/scenarios.json` — example scenarios for development (not graded).
- `samples/run_local.py` — run your planner on the samples and print the score.

Start by reading the task description, then implement `plan` and iterate with
`python3 samples/run_local.py`. Only the Python 3 standard library is available.
