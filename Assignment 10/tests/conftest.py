"""
tests/conftest.py — pytest configuration
Inserts the platform package directory onto sys.path so that
all module imports work when running `pytest tests/` from any CWD.
Also applies the _pathfix guard so stdlib 'platform' is not shadowed.
"""
import sys
from pathlib import Path

# Platform source root
ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

# Apply the path-fix so stdlib 'platform' wins over our platform.py
import importlib
_new_path = [p for p in sys.path if p != ""]
# Keep ROOT at back, not front
if str(ROOT) in _new_path:
    _new_path.remove(str(ROOT))
_new_path.append(str(ROOT))
sys.path[:] = _new_path

# Ensure stdlib platform module is loaded correctly
if "platform" in sys.modules and not hasattr(sys.modules["platform"], "python_implementation"):
    del sys.modules["platform"]
    importlib.import_module("platform")
