"""T15d (docs/test-plan.md): the T01 flow, then a tampered tally, judged against expected.json in this folder.
The change and the conditions it meets: ../tally_tamper.py; how to run: ../SETUP_T15.md."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from tally_tamper import main  # noqa: E402

if __name__ == "__main__":
    sys.exit(main("T15d"))
