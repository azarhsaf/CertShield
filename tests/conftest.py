import importlib.util
from pathlib import Path

RUNTIME_DEPS_AVAILABLE = all(
    importlib.util.find_spec(module) is not None for module in ("fastapi", "sqlalchemy")
)


def pytest_ignore_collect(collection_path: Path, config):
    if RUNTIME_DEPS_AVAILABLE:
        return False
    return collection_path.name.startswith("test_") and collection_path.name != "test_environment.py"
