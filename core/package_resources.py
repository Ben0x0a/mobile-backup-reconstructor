"""Lifetime of package data files materialised from importlib.resources.

Defines: `RESOURCE_STACK`, a process-lifetime ExitStack closed at exit.
Used by: core.ios_domain_map, core.android_reconstructor.
Depends on: nothing.
"""

from __future__ import annotations

import atexit
from contextlib import ExitStack

# Keeps resources materialised by `as_file` alive for the life of the process.
# WHY: `as_file` deletes what it extracted when its context exits, so a path
# returned from inside a `with` block is already gone by the time it is used.
RESOURCE_STACK = ExitStack()


atexit.register(RESOURCE_STACK.close)
