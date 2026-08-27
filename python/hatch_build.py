"""Hatch build hook: bundle the repo-level ``rules/`` and ``schema/`` into the wheel.

The Python package lives in ``python/`` while the ruleset and schemas are shared by
all language SDKs at the repo root. At build time we copy them into the package so
``pip install aitdp`` ships with the official rules. When building from an sdist
(no ``../rules``), the already-copied directories are used as-is.
"""

from __future__ import annotations

import shutil
from pathlib import Path

from hatchling.builders.hooks.plugin.interface import BuildHookInterface

_COPIES = {"rules": "_bundled_rules", "schema": "_schema"}


class BundleRulesHook(BuildHookInterface):
    PLUGIN_NAME = "custom"

    def initialize(self, version: str, build_data: dict) -> None:  # noqa: ARG002
        root = Path(self.root)
        pkg = root / "src" / "aitdp"
        for src_name, dst_name in _COPIES.items():
            src = root.parent / src_name
            dst = pkg / dst_name
            if src.is_dir():
                if dst.exists():
                    shutil.rmtree(dst)
                shutil.copytree(
                    src, dst, ignore=shutil.ignore_patterns("__pycache__", "*.md", ".*")
                )
            elif not dst.is_dir():
                raise FileNotFoundError(f"neither {src} nor {dst} exists; cannot bundle {src_name}")
