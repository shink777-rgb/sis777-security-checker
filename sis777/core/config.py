"""Load and save criteria.json (thresholds and lists)."""
from __future__ import annotations

import json
import os

from .usbguard import program_dir


def criteria_path() -> str:
    return os.path.join(program_dir(), "config", "criteria.json")


def load() -> dict:
    with open(criteria_path(), encoding="utf-8") as f:
        return json.load(f)


def save(cfg: dict) -> None:
    path = criteria_path()
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(cfg, f, ensure_ascii=False, indent=2)
    os.replace(tmp, path)
