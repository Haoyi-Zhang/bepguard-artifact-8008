"""Expose generated function-style tests to the standard-library runner."""
from __future__ import annotations

import importlib
import inspect
import unittest

TEST_MODULES = (
    "tests.test_clean_artifact_hygiene",
    "tests.test_locked_fixtures_generated",
    "tests.test_witness_certificates_generated",
)


def load_tests(
    loader: unittest.TestLoader,
    tests: unittest.TestSuite,
    pattern: str | None,
) -> unittest.TestSuite:
    """Build a unittest suite without requiring pytest or plug-ins."""
    suite = unittest.TestSuite()
    for module_name in TEST_MODULES:
        module = importlib.import_module(module_name)
        for name, function in sorted(vars(module).items()):
            if name.startswith("test_") and inspect.isfunction(function):
                signature = inspect.signature(function)
                if not signature.parameters:
                    suite.addTest(unittest.FunctionTestCase(function))
    return suite
