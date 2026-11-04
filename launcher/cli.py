"""Command-line launcher for the mobile backup reconstructor.

Defines: the CLI entry point, delegating straight to the reconstruction engine.
Used by: main.
Depends on: core.reconstructor.
"""

from __future__ import annotations

from core.reconstructor import main as run_reconstruction


def main(argv: list[str] | None = None) -> int:
    return run_reconstruction(argv)
