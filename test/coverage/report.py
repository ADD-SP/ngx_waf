#!/usr/bin/env python3
"""Print the coverage of the Rust core, module by module.

`llvm-cov` produces the numbers, this script only decides what to show.  The
tests of a module live in a `mod tests` block at the end of the same file and
their lines would otherwise count as covered code, so that block is left out
unless `--include-tests` is given.

Several lcov files can be given: the unit tests and the nginx suites run two
different binaries, and a line counts as covered when either of them reached
it.
"""

import argparse
import re
import sys
from functools import lru_cache
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SRC = ROOT / "rust" / "src"


@lru_cache(maxsize=None)
def test_start(path):
    """The line the `mod tests` block of a source file starts on, when it has
    one; `None` for a file whose whole content is production code."""
    try:
        with open(path, errors="replace") as handle:
            for number, line in enumerate(handle, start=1):
                if re.match(r"^mod tests \{", line):
                    return number
    except OSError:
        return None

    return None


def is_code(path, number, include_tests):
    """Whether the line is production code, i.e. not in the `mod tests` block
    at the end of the file."""
    if include_tests:
        return True

    start = test_start(path)
    return start is None or number < start


def parse_lcov(paths):
    """The union of the lcov files: line hits, function definition lines and
    function hits.  A line or a function of one file wins when any of them
    reached it."""
    lines = {}
    definitions = {}
    calls = {}

    for path in paths:
        with open(path, errors="replace") as handle:
            source = None

            for raw in handle:
                record = raw.strip()

                if record.startswith("SF:"):
                    source = record[3:]

                elif source and record.startswith("DA:"):
                    number, hits = record[3:].split(",")
                    key = (source, int(number))
                    lines[key] = max(lines.get(key, 0), int(hits))

                elif source and record.startswith("FN:"):
                    number, name = record[3:].split(",", 1)
                    definitions[(source, name)] = int(number)

                elif source and record.startswith("FNDA:"):
                    hits, name = record[5:].split(",", 1)
                    key = (source, name)
                    calls[key] = max(calls.get(key, 0), int(hits))

    return lines, definitions, calls


def collect(lines, definitions, calls, include_tests):
    """One row per module: `(ratio, name, hit, total, function hit, function
    total)` over the lines the caller asked for."""
    modules = {}

    for (path, number), hits in lines.items():
        if not path.startswith(f"{SRC}/") or not is_code(path, number, include_tests):
            continue

        module = modules.setdefault(path, [0, 0, 0, 0])
        module[0] += 1 if hits else 0
        module[1] += 1

    # A function is the same function in both binaries, but its mangled name is
    # not: the crate hash of a test build and of the one nginx links differ.
    # The definition line is what identifies it.
    functions = {}
    for (path, name), number in definitions.items():
        if path not in modules or not is_code(path, number, include_tests):
            continue

        key = (path, number)
        functions[key] = max(functions.get(key, 0), 1 if calls.get((path, name), 0) else 0)

    for (path, _), hit in functions.items():
        module = modules[path]
        module[2] += hit
        module[3] += 1

    rows = []
    for path, (hit, total, fn_hit, fn_total) in modules.items():
        name = path[len(f"{SRC}/") :]
        rows.append((100.0 * hit / total if total else 100.0, name, hit, total,
                     fn_hit, fn_total))

    rows.sort()
    return rows


def main():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("lcov", nargs="+", help="the lcov files to merge")
    parser.add_argument("--include-tests", action="store_true",
                        help="count the `mod tests` blocks as well")
    args = parser.parse_args()

    lines, definitions, calls = parse_lcov(args.lcov)
    rows = collect(lines, definitions, calls, args.include_tests)

    if not rows:
        print("no coverage of rust/src in the lcov files", file=sys.stderr)
        return 1

    header = (f"{'module':22} {'covered/total':>14} {'cover':>7} "
              f"{'missed':>7} {'functions':>11}")
    print(header)
    print("-" * len(header))

    total = [0, 0, 0, 0]
    for ratio, name, hit, count, fn_hit, fn_count in rows:
        total[0] += hit
        total[1] += count
        total[2] += fn_hit
        total[3] += fn_count
        print(f"{name:22} {hit:6d}/{count:<7d} {ratio:6.1f}% {count - hit:>7} "
              f"{fn_hit:5d}/{fn_count:<5d}")

    print("-" * len(header))
    print(f"{'TOTAL':22} {total[0]:6d}/{total[1]:<7d} "
          f"{100.0 * total[0] / total[1]:6.1f}% {total[1] - total[0]:>7} "
          f"{total[2]:5d}/{total[3]:<5d}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
