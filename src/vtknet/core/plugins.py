"""Plugin contract and discovery.

A plugin is a :class:`VtkPlugin` subclass discovered either from the
``vtknet.plugins`` entry-point group (pip-installed plugins) or from
``--plugin-dir`` directories of Python files (quick local plugins). Every
plugin becomes its own ``vtk <name>`` subcommand with its own arguments, and
participates in the standard JSON/HTML reporting pipeline.
"""

from __future__ import annotations

import argparse
import importlib.metadata
import importlib.util
import logging
from collections.abc import Iterator
from pathlib import Path
from typing import Any

from vtknet.core.engine import Engine
from vtknet.core.models import Finding

log = logging.getLogger("vtknet.plugins")

ENTRY_POINT_GROUP = "vtknet.plugins"


class VtkPlugin:
    """Base class every vtknet plugin must subclass.

    Class attributes ``name`` (subcommand) and ``help`` are required;
    ``add_arguments`` is optional; ``run`` returns the standard
    ``(findings, stats)`` tuple every other module produces.
    """

    name: str = ""
    help: str = ""

    def add_arguments(self, parser: argparse.ArgumentParser) -> None:
        """Register plugin-specific arguments on its subparser (optional)."""
        return

    def run(
        self, engine: Engine, args: argparse.Namespace
    ) -> tuple[list[Finding], dict[str, int]]:
        """Execute against the shared engine; returns (findings, stats)."""
        raise NotImplementedError


def _instantiate(obj: Any) -> VtkPlugin:
    return obj() if isinstance(obj, type) else obj


def _iter_entry_point_plugins() -> Iterator[VtkPlugin]:
    try:
        eps = importlib.metadata.entry_points(group=ENTRY_POINT_GROUP)
    except TypeError:  # pragma: no cover — py3.9 signature fallback
        eps = importlib.metadata.entry_points().get(ENTRY_POINT_GROUP, [])
    for ep in eps:
        try:
            obj = ep.load()
        except Exception as exc:  # noqa: BLE001 — one broken plugin must not kill the CLI
            log.warning("plugin entry point %r failed to load: %s", ep.name, exc)
            continue
        try:
            yield _instantiate(obj)
        except Exception as exc:  # noqa: BLE001
            log.warning("plugin %r failed to instantiate: %s", ep.name, exc)


def _plugins_from_module(mod: Any) -> list[VtkPlugin]:
    out: list[VtkPlugin] = []
    for attr in vars(mod).values():
        if isinstance(attr, type) and issubclass(attr, VtkPlugin) and attr is not VtkPlugin:
            out.append(_instantiate(attr))
    return out


def load_file_plugins(dir_path: str) -> list[VtkPlugin]:
    """Load plugin classes from *.py files in a directory."""
    plugins: list[VtkPlugin] = []
    root = Path(dir_path)
    if not root.is_dir():
        log.warning("plugin dir does not exist: %s", dir_path)
        return plugins
    for f in sorted(root.glob("*.py")):
        spec = importlib.util.spec_from_file_location(f"vtknet_plugin_{f.stem}", f)
        if spec is None or spec.loader is None:
            continue
        mod = importlib.util.module_from_spec(spec)
        try:
            spec.loader.exec_module(mod)
        except Exception as exc:  # noqa: BLE001 — a broken plugin file must not kill the CLI
            log.warning("plugin file %s failed to load: %s", f, exc)
            continue
        plugins.extend(_plugins_from_module(mod))
    return plugins


def discover(plugin_dirs: list[str] | None = None) -> list[VtkPlugin]:
    """All available plugins: entry points first, then file-based, deduped by name."""
    found: list[VtkPlugin] = list(_iter_entry_point_plugins())
    for d in plugin_dirs or []:
        found.extend(load_file_plugins(d))
    unique: dict[str, VtkPlugin] = {}
    for pl in found:
        if not pl.name:
            log.warning("plugin without a name ignored: %r", pl)
            continue
        unique.setdefault(pl.name, pl)
    return list(unique.values())


def register_subcommands(
    subparsers: argparse._SubParsersAction,
    common: argparse.ArgumentParser,
    plugins: list[VtkPlugin],
    builtin_names: set[str],
) -> None:
    """Attach every plugin as its own subcommand (builtin names win on collision)."""
    for pl in plugins:
        if pl.name in builtin_names:
            log.warning("plugin %r collides with a builtin command — skipped", pl.name)
            continue
        p = subparsers.add_parser(pl.name, parents=[common], help=f"[plugin] {pl.help}")
        pl.add_arguments(p)
        p.set_defaults(_plugin=pl)
