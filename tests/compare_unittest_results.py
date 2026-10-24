#!/usr/bin/env python3
"""Compare complete unittest logs by exact failed/error case identity, not totals.

Usage: python3 tests/compare_unittest_results.py BASE_LOG CANDIDATE_LOG
Exit zero means no new failures/errors; it does NOT mean the suite passed.
"""
import argparse
import json
from pathlib import Path
import re


def parse(path):
    text = Path(path).read_text()
    totals = re.findall(r'^Ran (\d+) tests? in ([0-9.]+)s$', text, re.M)
    summaries = re.findall(r'^(?:FAILED \([^\n]+\)|OK(?: \([^\n]+\))?)$', text, re.M)
    if len(totals) != 1 or len(summaries) != 1:
        raise ValueError('not a single complete unittest result: ' + str(path))
    problems = re.findall(r'^(FAIL|ERROR): (.+)$', text, re.M)
    if len(problems) != len(set(problems)):
        raise ValueError('duplicate case identifiers: ' + str(path))
    summary = summaries[0]
    if summary.startswith('FAILED'):
        failures = int((re.search(r'failures=(\d+)', summary) or [None, '0'])[1])
        errors = int((re.search(r'errors=(\d+)', summary) or [None, '0'])[1])
        if failures != sum(kind == 'FAIL' for kind, _ in problems) or errors != sum(kind == 'ERROR' for kind, _ in problems):
            raise ValueError('declared problem totals disagree with cases: ' + str(path))
    elif problems:
        raise ValueError('OK result contains failures/errors: ' + str(path))
    return {'tests': int(totals[0][0]), 'summary': summary,
            'problems': frozenset(problems)}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('baseline')
    parser.add_argument('candidate')
    args = parser.parse_args()
    baseline, candidate = parse(args.baseline), parse(args.candidate)
    added = sorted(candidate['problems'] - baseline['problems'])
    removed = sorted(baseline['problems'] - candidate['problems'])
    result = {'baseline_tests': baseline['tests'], 'candidate_tests': candidate['tests'],
              'baseline_summary': baseline['summary'], 'candidate_summary': candidate['summary'],
              'baseline_problem_count': len(baseline['problems']),
              'candidate_problem_count': len(candidate['problems']),
              'added': added, 'removed': removed, 'no_new_problems': not added,
              'fully_green': not candidate['problems']}
    print(json.dumps(result, indent=2))
    return 1 if added else 0


if __name__ == '__main__':
    raise SystemExit(main())
