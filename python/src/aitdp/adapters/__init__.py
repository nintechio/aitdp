"""Adapters that wrap third-party scanners as AITDP detectors.

Each adapter is import-guarded: importing this package never requires the
third-party dependency. Import the specific adapter you need::

    from aitdp.adapters.llm_guard import LLMGuardDetector
"""
