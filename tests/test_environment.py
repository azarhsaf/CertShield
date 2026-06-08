from tests.conftest import RUNTIME_DEPS_AVAILABLE


def test_runtime_dependency_environment_is_known():
    assert isinstance(RUNTIME_DEPS_AVAILABLE, bool)
