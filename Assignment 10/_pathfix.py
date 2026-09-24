"""
_pathfix.py — stdlib 'platform' module shadow guard.

Import this at the very top of any script that lives in this directory
and transitively imports pandas (which itself imports stdlib 'platform').
Since our platform.py file shadows the stdlib module when the CWD is on
sys.path, we remove/fix the path here.
"""
import sys
import importlib
from pathlib import Path

_HERE = str(Path(__file__).resolve().parent)

# Remove this directory from the FRONT of sys.path so stdlib wins.
_new_path = [p for p in sys.path if p not in ("", _HERE)]
# Keep our directory at the BACK so our sibling modules can still be found.
if _HERE not in _new_path:
    _new_path.append(_HERE)
sys.path[:] = _new_path

# If 'platform' was already imported and is our script, force reload stdlib.
if "platform" in sys.modules:
    pm = sys.modules["platform"]
    if not hasattr(pm, "python_implementation"):
        del sys.modules["platform"]
        importlib.import_module("platform")
