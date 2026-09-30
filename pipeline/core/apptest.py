#!/usr/bin/env python3
"""
apptest.py - check the desktop app's wiring without launching it.

A button with no handler does nothing and says nothing. A handler with no button
is dead code that reads like a feature. Both are invisible in review and both
have happened here, the second one within a minute of writing this file.

Nothing in here knows what any button does. It compares two lists.
"""
import io
import os
import re

HERE = os.path.dirname(os.path.abspath(__file__))
APP = os.path.join(os.path.dirname(os.path.dirname(HERE)), "app")

_BTN_ID = re.compile(r'id="(\w+Btn)"')
_WIRED = re.compile(r"\$\('#(\w+Btn)'\)")
# ipcRenderer channels the preload exposes, and the ones main.js answers
_PRELOAD = re.compile(r"invoke\(\s*'([\w-]+)'")
_HANDLE = re.compile(r"ipcMain\.handle\(\s*'([\w-]+)'")


def _read(*parts):
    p = os.path.join(APP, *parts)
    if not os.path.isfile(p):
        return None
    return io.open(p, encoding="utf-8").read()


def selftest():
    html = _read("renderer", "index.html")
    js = _read("renderer", "renderer.js")
    pre = _read("preload.js")
    main = _read("main.js")
    if html is None or js is None:
        return ["the app's renderer files are not where this expects them"]
    bad = []

    buttons = set(_BTN_ID.findall(html))
    wired = set(_WIRED.findall(js))
    for b in sorted(buttons - wired):
        bad.append("%s is a button in the page with no handler, so clicking it "
                   "does nothing and says nothing" % b)
    for w in sorted(wired - buttons):
        bad.append("%s has a handler but no button in the page, so the code "
                   "reads like a feature that cannot be reached" % w)

    if pre is not None and main is not None:
        asked = set(_PRELOAD.findall(pre))
        answered = set(_HANDLE.findall(main))
        for c in sorted(asked - answered):
            bad.append("the preload offers the channel %r and main.js does not "
                       "answer it, so that call rejects at runtime" % c)

    # every path the renderer opens should be a file this package writes
    opened = set(re.findall(r"outDir \+ '/([\w.]+)'", js))
    written = set()
    deob = _read("..", "pipeline", "deob.py") or ""
    for name in opened:
        if name in deob or name in (_read("..", "pipeline", "core",
                                          "driver.py") or ""):
            written.add(name)
    for name in sorted(opened - written):
        bad.append("the app offers to open %r, which nothing in the pipeline "
                   "writes" % name)

    print("app wiring selftest %s" % ("ok" if not bad else "FAILURES"))
    for b in bad:
        print("  - %s" % b)
    return bad


if __name__ == "__main__":
    raise SystemExit(1 if selftest() else 0)
