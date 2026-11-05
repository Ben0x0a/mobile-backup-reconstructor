"""iOS backup domain -> Full File System-like path mapping.

Defines: `DomainMap`, the YAML loaders (`load_domain_mounts` selects the shipped
map matching the iOS version), the dependency-free YAML fallback parser
(`parse_simple_domain_yaml`, also used for the Android map), and
`mapped_output_path`.
Used by: core.ios_backup, core.ios_reconstructor, core.ios_traceability,
core.android_reconstructor (parser only).
Depends on: core.errors, core.output_paths, core.package_resources,
config/domain_maps (package data).
"""

from __future__ import annotations

from functools import lru_cache
from importlib.resources import as_file, files
from pathlib import Path, PurePosixPath
from typing import Any

from core.errors import BackupError
from core.output_paths import (
    safe_join_path,
    safe_output_path,
)
from core.package_resources import RESOURCE_STACK

DomainMap = dict[str, Any]


@lru_cache(maxsize=1)
def default_domain_map_path() -> Path:
    """Locate the shipped domain-map directory.

    HOW: resolves ``config/domain_maps`` through importlib.resources, keeping
    any extracted copy open on a process-lifetime ExitStack.
    WHY: ``Path(__file__).parents[1]`` breaks when the package is installed
    into a zip, frozen by PyInstaller, or used as a namespace package.
    """
    resource = files("config").joinpath("domain_maps")
    return Path(RESOURCE_STACK.enter_context(as_file(resource)))


def parse_simple_domain_yaml(path: Path) -> DomainMap:
    sections = {"exact_domains": {}, "prefix_domains": {}}
    parsed: DomainMap = {**sections, "unknown_domain_template": "unknown_backup_domains/{domain}"}
    current_section: str | None = None
    for raw_line in path.read_text(encoding="utf-8").splitlines():
        line = raw_line.split("#", 1)[0].rstrip()
        if not line.strip():
            continue
        if not raw_line.startswith((" ", "\t")) and line.endswith(":"):
            current_section = line[:-1].strip()
            if current_section not in parsed:
                parsed[current_section] = {}
            continue
        if not raw_line.startswith((" ", "\t")) and ":" in line:
            key, value = line.split(":", 1)
            parsed[key.strip()] = value.strip().strip("'\"")
            current_section = None
            continue
        if current_section is not None and ":" in line:
            key, value = line.split(":", 1)
            parsed[current_section][key.strip().strip("'\"")] = value.strip().strip("'\"")
            continue
        raise BackupError(f"Unsupported domain mapping YAML line in {path}: {raw_line}")
    return parsed


def parse_version_tuple(version: str | None) -> tuple[int, ...] | None:
    if not version:
        return None
    parts: list[int] = []
    for part in str(version).split("."):
        digits = "".join(ch for ch in part if ch.isdigit())
        if not digits:
            break
        parts.append(int(digits))
    return tuple(parts) if parts else None


def compare_versions(left: tuple[int, ...], right: tuple[int, ...]) -> int:
    width = max(len(left), len(right))
    padded_left = left + (0,) * (width - len(left))
    padded_right = right + (0,) * (width - len(right))
    return (padded_left > padded_right) - (padded_left < padded_right)


def ios_version_matches_range(version: str | None, ios_range: Any) -> bool:
    parsed_version = parse_version_tuple(version)
    if parsed_version is None:
        return True
    if not isinstance(ios_range, dict):
        return True
    min_version = parse_version_tuple(ios_range.get("min"))
    max_version = parse_version_tuple(ios_range.get("max"))
    if min_version is not None and compare_versions(parsed_version, min_version) < 0:
        return False
    if max_version is not None and compare_versions(parsed_version, max_version) > 0:
        return False
    return True


def load_domain_map_yaml(map_path: Path) -> DomainMap:
    try:
        import yaml  # type: ignore
    except ImportError:
        data = parse_simple_domain_yaml(map_path)
    else:
        with map_path.open("r", encoding="utf-8") as fh:
            loaded = yaml.safe_load(fh) or {}
        if not isinstance(loaded, dict):
            raise BackupError(f"Domain mapping file must contain a YAML mapping: {map_path}")
        data = loaded
    exact = data.get("exact_domains", {})
    prefixes = data.get("prefix_domains", {})
    unknown = data.get("unknown_domain_template", "unknown_backup_domains/{domain}")
    ios_versions = data.get("ios_versions", {})
    name = data.get("name", map_path.stem)
    if not isinstance(exact, dict) or not isinstance(prefixes, dict) or not isinstance(unknown, str):
        raise BackupError(f"Invalid domain mapping file structure: {map_path}")
    if ios_versions is None:
        ios_versions = {}
    if not isinstance(ios_versions, dict):
        raise BackupError(f"Invalid ios_versions header in domain mapping file: {map_path}")
    return {
        "name": str(name),
        "ios_versions": {str(k): str(v) for k, v in ios_versions.items()},
        "exact_domains": {str(k): str(v) for k, v in exact.items()},
        "prefix_domains": {str(k): str(v) for k, v in prefixes.items()},
        "unknown_domain_template": unknown,
        "path": str(map_path),
    }


def load_domain_mounts(path: Path | None = None, ios_version: str | None = None) -> DomainMap:
    map_path = (path or default_domain_map_path()).expanduser()
    if map_path.is_dir():
        candidates = sorted(p for p in map_path.iterdir() if p.suffix.lower() in (".yaml", ".yml"))
        if not candidates:
            raise BackupError(f"Domain mapping directory contains no YAML files: {map_path}")
        first_valid: DomainMap | None = None
        for candidate in candidates:
            domain_map = load_domain_map_yaml(candidate)
            if first_valid is None:
                first_valid = domain_map
            if ios_version_matches_range(ios_version, domain_map.get("ios_versions")):
                return domain_map
        if first_valid is not None:
            return first_valid
    if not map_path.is_file():
        raise BackupError(f"Domain mapping file or directory not found: {map_path}")
    return load_domain_map_yaml(map_path)


def filesystem_domain_root(domain: str, domain_map: DomainMap | None = None) -> str:
    domain_map = domain_map or load_domain_mounts()
    exact = domain_map["exact_domains"]
    if domain in exact:
        return exact[domain]
    for prefix, template in domain_map["prefix_domains"].items():
        if domain.startswith(prefix):
            suffix = domain[len(prefix) :]
            return str(template).format(domain=domain, suffix=suffix)
    return str(domain_map["unknown_domain_template"]).format(domain=domain)


def mapped_output_path(
    domain: str,
    relative_path: str,
    output_layout: str,
    domain_map: DomainMap | None = None,
) -> PurePosixPath:
    if output_layout == "backup":
        return safe_output_path(domain, relative_path)
    if output_layout == "filesystem":
        return safe_join_path(filesystem_domain_root(domain, domain_map), relative_path)
    raise BackupError(f"Unsupported output layout: {output_layout}")
