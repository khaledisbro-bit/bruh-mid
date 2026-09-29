#!/usr/bin/env python3
"""
collect.py - pick the captures up off the executor, so nobody has to copy them.

An executor writes each run to the same two files in its workspace folder, and
the next run overwrites them. Doing this by hand means finding that folder,
copying two files the moment a run ends, renaming them, and not losing one to
the run after - every time, for every run.

This watches those files instead. When a run finishes writing them, the pair is
copied out under that run's own name, and the next run is waited for. The
console copy is not used: an executor prints only the first few thousand
instructions, while the file beside it holds them all.

A run is taken as finished when both files stop changing. That matters more than
it sounds: a file caught mid-write is a truncated capture that analyses cleanly
and describes a program that stops halfway.
"""
import os
import shutil
import time

BLOCK = "unobf_result.txt"
DUMP = "opcode_trace.txt"
EXTRA = "resolved_constants.txt"
# The harness also writes the interpreter it found. Its handlers say what each
# opcode does, which a short run cannot establish on its own.
INNER = "inner_chunk_1.txt"
SETTLE = 2.0            # seconds a file must stay unchanged to count as written
POLL = 0.5


def _roots():
    out = []
    home = os.path.expanduser("~")
    for d in (home, os.path.join(home, "Downloads"), os.path.join(home, "Desktop"),
              os.path.join(home, "Documents"), os.getcwd()):
        if os.path.isdir(d):
            out.append(d)
    if os.name == "nt":
        for letter in "CDEF":
            d = letter + ":\\"
            if os.path.isdir(d):
                out.append(d)
    return out


def find_workspaces(hint=None, max_depth=5):
    """Directories that hold an executor's output.

    Searched for by the file the harness writes, not by the executor's name, so
    it does not matter which executor wrote it."""
    if hint:
        if os.path.isdir(hint):
            return [hint]
        raise SystemExit("no such folder: %s" % hint)
    found, seen = [], set()
    skip = {"node_modules", ".git", "__pycache__", "AppData", "Windows",
            "Program Files", "Program Files (x86)", "$Recycle.Bin"}
    for root in _roots():
        base = root.rstrip("\\/").count(os.sep)
        for dirpath, dirnames, filenames in os.walk(root, topdown=True):
            if dirpath.count(os.sep) - base >= max_depth:
                dirnames[:] = []
                continue
            dirnames[:] = [d for d in dirnames
                           if d not in skip and not d.startswith(".")]
            if BLOCK in filenames or DUMP in filenames:
                real = os.path.realpath(dirpath)
                if real not in seen:
                    seen.add(real)
                    found.append(dirpath)
    return found


def _stamp(path):
    try:
        st = os.stat(path)
        return (st.st_mtime, st.st_size)
    except OSError:
        return None


def _settled(ws, previous):
    """The pair as it stands, once both files have stopped changing and at least
    one of them differs from what was collected last time."""
    now = {n: _stamp(os.path.join(ws, n)) for n in (BLOCK, DUMP, EXTRA)}
    if now[BLOCK] is None and now[DUMP] is None:
        return None
    if all(now[n] == previous.get(n) for n in (BLOCK, DUMP)):
        return None
    time.sleep(SETTLE)
    again = {n: _stamp(os.path.join(ws, n)) for n in (BLOCK, DUMP, EXTRA)}
    if any(again[n] != now[n] for n in (BLOCK, DUMP)):
        return None          # still being written; wait for the next poll
    return again


def watch(workspaces, runs, outdir, log=print, timeout=None):
    """Collect `runs` runs. Returns the argument for each run, with the two
    files of one run joined so they stay one run."""
    os.makedirs(outdir, exist_ok=True)
    state = {ws: {} for ws in workspaces}
    for ws in workspaces:
        state[ws] = {n: _stamp(os.path.join(ws, n))
                     for n in (BLOCK, DUMP, EXTRA)}
    log("watching for runs in:")
    for ws in workspaces:
        log("   " + ws)
    log("run the harness in your executor. Collecting %d run(s); "
        "press Ctrl+C to stop early." % runs)

    got, started = [], time.time()
    try:
        while len(got) < runs:
            for ws in workspaces:
                fresh = _settled(ws, state[ws])
                if not fresh:
                    continue
                state[ws] = fresh
                n = len(got) + 1
                parts = []
                for name, tag in ((BLOCK, "block"), (DUMP, "dump"),
                                  (EXTRA, "consts"), (INNER, "vm")):
                    src = os.path.join(ws, name)
                    if not os.path.isfile(src):
                        continue
                    dst = os.path.join(outdir, "run%d_%s.txt" % (n, tag))
                    shutil.copy2(src, dst)
                    # the constants dump is evidence too: the printed block
                    # caps its list, and the file does not
                    if tag in ("block", "dump", "consts"):
                        parts.append(dst)
                if not parts:
                    continue
                got.append("+".join(parts))
                log("  run %d collected: %s"
                    % (n, ", ".join(os.path.basename(p) for p in parts)))
                if len(got) >= runs:
                    break
            if timeout and time.time() - started > timeout:
                log("  stopped waiting after %ds" % timeout)
                break
            time.sleep(POLL)
    except KeyboardInterrupt:
        log("\n  stopped; keeping the %d run(s) collected so far" % len(got))
    return got
