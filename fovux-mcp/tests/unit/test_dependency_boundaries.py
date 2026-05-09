"""Dependency boundary tests for optional backend integrations."""

from __future__ import annotations

import importlib
import sys
import tomllib
from pathlib import Path


def test_core_import_does_not_import_ultralytics() -> None:
    """Importing Fovux core modules should not load the optional YOLO backend."""
    sys.modules.pop("ultralytics", None)

    importlib.import_module("fovux")
    importlib.import_module("fovux.core.auth")

    assert "ultralytics" not in sys.modules


def test_ultralytics_is_declared_as_optional_extra() -> None:
    """The package metadata should keep AGPL/commercial-boundary deps optional."""
    pyproject = Path(__file__).resolve().parents[2] / "pyproject.toml"
    payload = tomllib.loads(pyproject.read_text(encoding="utf-8"))

    dependencies = payload["project"]["dependencies"]
    optional = payload["project"]["optional-dependencies"]

    assert all(not str(dep).startswith("ultralytics") for dep in dependencies)
    assert any(str(dep).startswith("ultralytics") for dep in optional["yolo"])
