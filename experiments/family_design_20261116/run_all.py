"""Run the family-design pilot, threshold sensitivity, transfer tests, and report."""
from __future__ import annotations
import subprocess
import sys
from pathlib import Path

HERE=Path(__file__).resolve().parent
ROOT=HERE.parents[1]
STEPS=('evaluate_families.py','evaluate_thresholds.py','cross_dataset.py','analyze_results.py')

def main():
    for step in STEPS:
        print(f'\n=== {step} ===',flush=True)
        proc=subprocess.run([sys.executable,str(HERE/step)],cwd=ROOT)
        if proc.returncode:
            print(f'Failed at {step} (exit {proc.returncode}); later steps were not run.',file=sys.stderr)
            return proc.returncode
    print('\nCompleted. Feature-set and two-level variants are skipped when the paired bootstrap does not establish a family-level gain.')
    return 0

if __name__=='__main__': raise SystemExit(main())
