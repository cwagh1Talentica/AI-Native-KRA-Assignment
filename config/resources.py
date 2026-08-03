"""Configuration resource loading helpers."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict


_DATA_DIR = Path(__file__).parent / "data"


def load_json_resource(filename: str) -> Any:
    """Load JSON content from config/data."""

    path = _DATA_DIR / filename
    with path.open("r", encoding="utf-8") as handle:
        return json.load(handle)


def load_mapping(filename: str) -> Dict[str, Any]:
    """Load a JSON mapping from config/data."""

    loaded = load_json_resource(filename)
    if not isinstance(loaded, dict):
        raise ValueError(f"Expected a JSON object in {filename}")
    return loaded
