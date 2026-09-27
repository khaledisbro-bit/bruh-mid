"""Obfuscator family plugins.

Each plugin module exposes:
    NAME : str
    def detect(src: str) -> bool          # cheap check: is this my family?
    def unwrap(src, log) -> (inner_source_bytes, inner_data_bytes) | (None, None)

The loader tries every plugin's detect(); the first match handles the sample.
Add a new family by dropping a module here, no core changes needed.
"""
import importlib
import pkgutil
import os

_PLUGINS = None


def load_plugins():
    global _PLUGINS
    if _PLUGINS is not None:
        return _PLUGINS
    plugins = []
    pkg_dir = os.path.dirname(__file__)
    for mod in pkgutil.iter_modules([pkg_dir]):
        if mod.name.startswith("_"):
            continue
        m = importlib.import_module(f"{__name__}.{mod.name}")
        if hasattr(m, "detect") and hasattr(m, "unwrap"):
            plugins.append(m)
    _PLUGINS = plugins
    return plugins


def pick(src):
    """Return the first plugin whose detect() matches, or None."""
    for p in load_plugins():
        try:
            if p.detect(src):
                return p
        except Exception:
            continue
    return None
