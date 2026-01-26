#!/usr/bin/env python3
"""
agc_install.py

Install Ansible collections with a resilient strategy:

1) Standard path:
   Uses `ansible-galaxy collection install <namespace.collection>[==x.y.z] ...`.

2) Fallback workaround (offline from Galaxy):
   Resolves the collection repository on GitHub, clones the desired tag,
   builds a local tarball via `ansible-galaxy collection build`, and installs
   it via `ansible-galaxy collection install <tar.gz> --no-deps ...`.

Key features:
- Repository resolution with fallbacks:
  Handles collections that have a versioned dependency name like
  `community.library_inventory_filtering_v1` while the GitHub repo is
  `community.library_inventory_filtering`.
- Optional repository overrides via a JSON/YAML mapping file.
- Dependency handling in workaround mode (offline):
  Best-effort or strict recursion based on `--deps-mode`.
- Basic version constraint support for dependency specifications.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Set, Tuple

SEMVER_TAG_RE = re.compile(r"^v?(\d+)\.(\d+)\.(\d+)$")
COLLECTION_RE = re.compile(r"^[A-Za-z0-9_]+\.[A-Za-z0-9_]+$")
V_SUFFIX_RE = re.compile(r"^(?P<base>.+)_v(?P<n>\d+)$")


def ensure_cmd(name: str) -> None:
    """
    Ensure an executable is available on PATH.

    Args:
        name: The executable name (e.g. "git", "ansible-galaxy").

    Raises:
        SystemExit: If the executable cannot be found on PATH.
    """
    if shutil.which(name) is None:
        raise SystemExit(f"ERROR: missing dependency '{name}' in PATH")


def run(cmd: List[str], *, cwd: Optional[Path] = None, check: bool = False) -> subprocess.CompletedProcess:
    """
    Execute a command without capturing stdout/stderr.

    This is suitable for commands where streaming output to the console
    is desirable.

    Args:
        cmd: Command and arguments as a list (no shell).
        cwd: Optional working directory.
        check: If True, raise CalledProcessError on non-zero exit code.

    Returns:
        A CompletedProcess with returncode, args, etc.
    """
    return subprocess.run(cmd, cwd=str(cwd) if cwd else None, check=check, text=True)


def run_capture(cmd: List[str], *, cwd: Optional[Path] = None) -> subprocess.CompletedProcess:
    """
    Execute a command and capture stdout/stderr.

    Args:
        cmd: Command and arguments as a list (no shell).
        cwd: Optional working directory.

    Returns:
        A CompletedProcess with stdout and stderr populated.
    """
    return subprocess.run(
        cmd,
        cwd=str(cwd) if cwd else None,
        check=False,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )


def parse_collection_spec(spec: str) -> Tuple[str, Optional[str]]:
    """
    Parse a collection spec in the form `namespace.collection` or `namespace.collection==x.y.z`.

    Args:
        spec: Collection spec string.

    Returns:
        Tuple of (collection_name, version) where version is None if not specified.

    Examples:
        "community.docker" -> ("community.docker", None)
        "community.docker==5.0.5" -> ("community.docker", "5.0.5")
    """
    if "==" in spec:
        name, ver = spec.split("==", 1)
        name = name.strip()
        ver = ver.strip().lstrip("v")
        return name, ver
    return spec.strip(), None


def semver_tuple(tag: str) -> Optional[Tuple[int, int, int]]:
    """
    Convert a tag of the form `vX.Y.Z` or `X.Y.Z` into a comparable tuple.

    Args:
        tag: Tag string.

    Returns:
        (major, minor, patch) if the tag matches the expected pattern, otherwise None.
    """
    m = SEMVER_TAG_RE.match(tag)
    if not m:
        return None
    return int(m.group(1)), int(m.group(2)), int(m.group(3))


def pick_exact_tag(tags: Iterable[str], version: str) -> Optional[str]:
    """
    Choose an exact tag matching a given semantic version.

    The function prefers a `v`-prefixed tag (e.g. `v1.2.3`) if present, otherwise
    it falls back to the plain tag (`1.2.3`).

    Args:
        tags: Iterable of tag names.
        version: Version string "X.Y.Z" (without leading "v").

    Returns:
        The matching tag name or None if no exact match exists.
    """
    if f"v{version}" in tags:
        return f"v{version}"
    if version in tags:
        return version
    return None


def pick_latest_tag(tags: Iterable[str]) -> Tuple[str, str]:
    """
    Pick the highest semantic version tag.

    Args:
        tags: Iterable of tag names. Only tags matching `vX.Y.Z` or `X.Y.Z` are considered.

    Returns:
        (tag, resolved_version) where resolved_version is "X.Y.Z" without a `v` prefix.

    Raises:
        RuntimeError: If no semantic version tags are found.
    """
    best: Optional[Tuple[Tuple[int, int, int], str, str]] = None
    for t in tags:
        st = semver_tuple(t)
        if st is None:
            continue
        ver = f"{st[0]}.{st[1]}.{st[2]}"
        if best is None or st > best[0]:
            best = (st, t, ver)
    if best is None:
        raise RuntimeError("No semver tags found (expected tags like v1.2.3 or 1.2.3)")
    return best[1], best[2]


def parse_constraints(spec: str) -> List[Tuple[str, Tuple[int, int, int]]]:
    """
    Parse a comparator-based semantic version constraint list.

    Supports: ==, >=, >, <=, < with comma-separated items.
    Example: ">=1.0.0,<2.0.0"

    Args:
        spec: Constraint string.

    Returns:
        A list of (operator, version_tuple) pairs.

    Raises:
        ValueError: If any constraint component is unsupported or malformed.
    """
    out: List[Tuple[str, Tuple[int, int, int]]] = []
    for part in [p.strip() for p in spec.split(",") if p.strip()]:
        m = re.match(r"^(==|>=|<=|>|<)\s*v?(\d+\.\d+\.\d+)\s*$", part)
        if not m:
            raise ValueError(f"Unsupported constraint: {part!r}")
        op = m.group(1)
        v = m.group(2)
        st = semver_tuple(v)
        if st is None:
            raise ValueError(f"Invalid version in constraint: {part!r}")
        out.append((op, st))
    return out


def satisfies(st: Tuple[int, int, int], constraints: List[Tuple[str, Tuple[int, int, int]]]) -> bool:
    """
    Test whether a semantic version tuple satisfies a list of constraints.

    Args:
        st: Version tuple to test (major, minor, patch).
        constraints: Parsed constraints from `parse_constraints()`.

    Returns:
        True if all constraints are satisfied, otherwise False.
    """
    for op, ref in constraints:
        if op == "==":
            if st != ref:
                return False
        elif op == ">=":
            if st < ref:
                return False
        elif op == ">":
            if st <= ref:
                return False
        elif op == "<=":
            if st > ref:
                return False
        elif op == "<":
            if st >= ref:
                return False
        else:
            return False
    return True


def resolve_tag(tags: Iterable[str], constraint: Optional[str]) -> Tuple[str, str]:
    """
    Resolve a Git tag from a list of tags given an optional version constraint.

    Args:
        tags: Iterable of tag names (e.g. from `git ls-remote --tags`).
        constraint:
            - None / "" / "*" / "latest" => latest semver
            - "==x.y.z" or "x.y.z" => exact match
            - comparator list like ">=x.y.z,<a.b.c" => best matching semver

    Returns:
        (tag, resolved_version_without_v)

    Raises:
        RuntimeError: If no suitable tag is found for the constraint.
        ValueError: If the constraint uses unsupported syntax.
    """
    tags_list = list(tags)
    if not constraint or constraint.strip() in {"*", "latest"}:
        return pick_latest_tag(tags_list)

    c = constraint.strip()
    if c.startswith("=="):
        c = c[2:].strip()
    c = c.lstrip("v")

    if re.fullmatch(r"\d+\.\d+\.\d+", c):
        tag = pick_exact_tag(tags_list, c)
        if not tag:
            raise RuntimeError(f"Cannot find tag for version {c} (tried v{c} and {c})")
        return tag, c

    # comparator constraints
    constraints = parse_constraints(constraint)
    candidates: List[Tuple[Tuple[int, int, int], str, str]] = []
    for t in tags_list:
        st = semver_tuple(t)
        if st is None:
            continue
        if satisfies(st, constraints):
            ver = f"{st[0]}.{st[1]}.{st[2]}"
            candidates.append((st, t, ver))
    if not candidates:
        raise RuntimeError(f"No tag matches constraint '{constraint}'")
    candidates.sort(key=lambda x: x[0])
    _, tag, ver = candidates[-1]
    return tag, ver


def try_import_yaml():
    """
    Try importing PyYAML.

    Returns:
        The imported `yaml` module if available, otherwise None.

    Notes:
        YAML support is optional and only needed when reading a YAML repo-map file
        or when parsing `galaxy.yml` dependencies via PyYAML.
    """
    try:
        import yaml  # type: ignore
        return yaml
    except Exception:
        return None


def load_repo_map(path: Optional[str]) -> Dict[str, str]:
    """
    Load an optional repository mapping file.

    The mapping allows special-casing repository URLs for collections whose
    GitHub repository name does not match `namespace.collection`.

    Supported file formats:
      - JSON: {"collection.name": "https://github.com/org/repo"}
      - YAML: same mapping (requires PyYAML)

    Args:
        path: Path to the mapping file, or None to disable.

    Returns:
        A mapping of collection -> repo_url.

    Raises:
        SystemExit: If the file does not exist or has invalid content/format.
    """
    if not path:
        return {}
    p = Path(path)
    if not p.exists():
        raise SystemExit(f"ERROR: repo-map file not found: {p}")

    if p.suffix.lower() in {".yaml", ".yml"}:
        yaml = try_import_yaml()
        if not yaml:
            raise SystemExit("ERROR: repo-map YAML requires PyYAML (pip install pyyaml) or use JSON instead.")
        data = yaml.safe_load(p.read_text(encoding="utf-8")) or {}
    else:
        data = json.loads(p.read_text(encoding="utf-8") or "{}")

    if not isinstance(data, dict):
        raise SystemExit("ERROR: repo-map must be a dict mapping collection -> repo_url")

    out: Dict[str, str] = {}
    for k, v in data.items():
        if not isinstance(k, str) or not isinstance(v, str):
            raise SystemExit("ERROR: repo-map keys/values must be strings")
        out[k.strip()] = v.strip()
    return out


def parse_dependencies(repo_dir: Path) -> Dict[str, Optional[str]]:
    """
    Parse collection dependencies from `galaxy.yml` / `galaxy.yaml`.

    The function tries to use PyYAML if available. If PyYAML is missing,
    it falls back to a minimal parser that supports only the dictionary
    form (YAML mapping) for dependencies.

    Args:
        repo_dir: Repository directory containing galaxy.yml or galaxy.yaml.

    Returns:
        Mapping of dependency collection name -> constraint (string) or None.

    Examples:
        dependencies:
          community.crypto: ">=2.0.0,<3.0.0"
          ansible.posix: "*"
    """
    yml = repo_dir / "galaxy.yml"
    if not yml.exists():
        yml = repo_dir / "galaxy.yaml"
    if not yml.exists():
        return {}

    yaml = try_import_yaml()
    if yaml:
        data = yaml.safe_load(yml.read_text(encoding="utf-8")) or {}
        deps = data.get("dependencies") or {}
        if isinstance(deps, dict):
            out: Dict[str, Optional[str]] = {}
            for k, v in deps.items():
                out[str(k)] = None if v in (None, "", "*") else str(v)
            return out
        if isinstance(deps, list):
            out2: Dict[str, Optional[str]] = {}
            for item in deps:
                if isinstance(item, str):
                    out2[item] = None
            return out2
        return {}

    # minimal fallback (dict-style only)
    out3: Dict[str, Optional[str]] = {}
    in_deps = False
    for line in yml.read_text(encoding="utf-8").splitlines():
        if re.match(r"^\s*dependencies:\s*$", line):
            in_deps = True
            continue
        if in_deps and re.match(r"^\S", line):
            in_deps = False
        if not in_deps:
            continue
        m = re.match(r"^\s+([A-Za-z0-9_]+\.[A-Za-z0-9_]+)\s*:\s*(.*?)\s*$", line)
        if m:
            name = m.group(1)
            val = m.group(2).strip().strip("'\"")
            out3[name] = None if val in ("", "*") else val
    return out3


def newest_tarball(repo_dir: Path) -> Path:
    """
    Find the newest built collection tarball in a repository directory.

    Args:
        repo_dir: Directory that should contain one or more `*.tar.gz` files.

    Returns:
        Path to the most recently modified tarball.

    Raises:
        RuntimeError: If no tarballs exist in the directory.
    """
    files = list(repo_dir.glob("*.tar.gz"))
    if not files:
        raise RuntimeError(f"No .tar.gz produced in {repo_dir}")
    return max(files, key=lambda p: p.stat().st_mtime)


@dataclass(frozen=True)
class Config:
    """
    Immutable runtime configuration for the installer.

    Attributes:
        mode:
            - "auto": try Galaxy first; on failure, use workaround.
            - "galaxy": only use Galaxy installation.
            - "workaround": only use the GitHub clone/build/install workaround.
        repo_base: Base URL used for deriving repository URLs (e.g. GitHub org path).
        repo_url_primary: Optional explicit repository URL for the primary collection only.
        repo_map: Optional mapping of collection -> repo URL for special cases.
        keep_workdir: If True, persist the temporary workaround directory under the current working directory.
        deps_mode:
            - "none": do not attempt dependency installation in workaround mode.
            - "best-effort": try dependency installation; warn on failure.
            - "strict": fail if any dependency installation fails.
    """

    mode: str  # auto|galaxy|workaround
    repo_base: str
    repo_url_primary: Optional[str]
    repo_map: Dict[str, str]
    keep_workdir: bool
    deps_mode: str  # none|best-effort|strict


class RepoResolver:
    """
    Resolve a collection name to a reachable git repository URL.

    Strategy:
    - Primary collection may have an explicit `repo_url_primary`.
    - Next, consult `repo_map`.
    - Otherwise, attempt derived URLs using `repo_base` and heuristics:
      - Try `<base>/<namespace.collection>` and `<base>/<namespace.collection>.git`
      - If the collection name ends in `_vN`, also try dropping the suffix:
        `namespace.name_v1` -> `namespace.name`
    """

    def __init__(self, cfg: Config) -> None:
        """
        Args:
            cfg: Installer configuration containing repo base, overrides, and mapping.
        """
        self.cfg = cfg

    def _candidates(self, collection: str, *, primary: bool) -> List[str]:
        """
        Generate candidate repository URLs for a given collection.

        Args:
            collection: Collection name `namespace.collection`.
            primary: True if this is the primary collection (not a dependency).

        Returns:
            A list of candidate repository URLs ordered by preference.
        """
        if primary and self.cfg.repo_url_primary:
            return [self.cfg.repo_url_primary]

        if collection in self.cfg.repo_map:
            return [self.cfg.repo_map[collection]]

        base = self.cfg.repo_base.rstrip("/")
        cands: List[str] = []

        def add(url: str) -> None:
            if url not in cands:
                cands.append(url)

        # canonical guess
        add(f"{base}/{collection}")
        add(f"{base}/{collection}.git")

        # heuristic for *_vN collections (drop suffix)
        ns, name = collection.split(".", 1)
        m = V_SUFFIX_RE.match(name)
        if m:
            name2 = m.group("base")
            alt = f"{ns}.{name2}"
            add(f"{base}/{alt}")
            add(f"{base}/{alt}.git")

        return cands

    def resolve(self, collection: str, *, primary: bool) -> str:
        """
        Resolve the first reachable repository URL for a collection.

        This method probes each candidate via `git ls-remote`.

        Args:
            collection: Collection name `namespace.collection`.
            primary: True if this is the primary collection (not a dependency).

        Returns:
            A repository URL that can be reached via git.

        Raises:
            RuntimeError: If no candidate repositories can be reached.
        """
        tried: List[str] = []
        for url in self._candidates(collection, primary=primary):
            tried.append(url)
            cp = run_capture(["git", "ls-remote", "--heads", "--refs", url])
            if cp.returncode == 0:
                return url
        raise RuntimeError(
            f"Cannot resolve git repository for {collection}. Tried: {', '.join(tried)}"
        )


class Installer:
    """
    Installer implementing Galaxy-first installation with an offline workaround fallback.

    Workaround mode mechanics:
    - Resolve git repository URL.
    - Determine tag to checkout based on version constraint.
    - Clone tag shallow.
    - Optionally recurse into dependencies by reading galaxy.yml.
    - Build the collection tarball.
    - Install tarball with `--no-deps` to avoid Galaxy dependency resolution.
    """

    def __init__(self, cfg: Config, passthrough_args: List[str]) -> None:
        """
        Args:
            cfg: Runtime configuration.
            passthrough_args: Arguments that will be forwarded to `ansible-galaxy collection install`,
                such as `--force`, `-p`, etc.
        """
        self.cfg = cfg
        self.passthrough_args = passthrough_args
        self.visited: Set[str] = set()
        self.resolver = RepoResolver(cfg)

    def git_list_tags(self, repo_url: str) -> List[str]:
        """
        List tag names from a remote git repository.

        Args:
            repo_url: Remote git repository URL.

        Returns:
            List of tag names without `refs/tags/` prefix.

        Raises:
            RuntimeError: If `git ls-remote` fails.
        """
        cp = run_capture(["git", "ls-remote", "--tags", "--refs", repo_url])
        if cp.returncode != 0:
            raise RuntimeError(f"git ls-remote failed for {repo_url}:\n{cp.stderr.strip()}")
        tags: List[str] = []
        for line in (cp.stdout or "").splitlines():
            parts = line.split()
            if len(parts) != 2:
                continue
            ref = parts[1]
            if ref.startswith("refs/tags/"):
                tags.append(ref.replace("refs/tags/", ""))
        return tags

    def galaxy_install(self, collection: str, version: Optional[str]) -> int:
        """
        Install a collection via the standard Galaxy mechanism.

        Args:
            collection: Collection name `namespace.collection`.
            version: Optional exact version string "X.Y.Z".

        Returns:
            The process return code from `ansible-galaxy`.
        """
        spec = f"{collection}=={version}" if version else collection
        cmd = ["ansible-galaxy", "collection", "install", spec, *self.passthrough_args]
        return run(cmd, check=False).returncode

    def workaround_install(self, collection: str, version: Optional[str]) -> None:
        """
        Install a collection using the offline workaround.

        The workaround creates a temporary workspace (or a persistent one if
        `keep_workdir` is enabled) that contains cloned repositories and built tarballs.

        Args:
            collection: Collection name `namespace.collection`.
            version: Optional exact version string "X.Y.Z".

        Raises:
            RuntimeError: If cloning/building/installing fails.
        """
        with tempfile.TemporaryDirectory(prefix="agc-install-") as td:
            workdir = Path(td)
            if self.cfg.keep_workdir:
                persist = Path.cwd() / f".agc-workdir-{os.getpid()}"
                if persist.exists():
                    shutil.rmtree(persist)
                shutil.move(str(workdir), persist)
                workdir = persist

            offline_dir = workdir / "offline"
            repos_dir = workdir / "repos"
            offline_dir.mkdir(parents=True, exist_ok=True)
            repos_dir.mkdir(parents=True, exist_ok=True)

            self._workaround_install_one(
                workdir=workdir,
                offline_dir=offline_dir,
                repos_dir=repos_dir,
                collection=collection,
                constraint=(f"=={version}" if version else None),
                primary=True,
            )

    def _workaround_install_one(
        self,
        *,
        workdir: Path,
        offline_dir: Path,
        repos_dir: Path,
        collection: str,
        constraint: Optional[str],
        primary: bool,
    ) -> None:
        """
        Workhorse for workaround installation (supports recursion into dependencies).

        Args:
            workdir: Root workspace directory.
            offline_dir: Directory where built tarballs are stored.
            repos_dir: Directory where repositories are cloned.
            collection: Collection name `namespace.collection`.
            constraint: Optional constraint (exact or comparator list) for selecting a git tag.
            primary: True if this is the primary collection (not a dependency).

        Raises:
            RuntimeError: On repository resolution, cloning, building, or installation failures.
        """
        if collection in self.visited:
            return
        self.visited.add(collection)

        repo_url = self.resolver.resolve(collection, primary=primary)
        tags = self.git_list_tags(repo_url)

        tag, _resolved_ver = resolve_tag(tags, constraint)

        repo_dir = repos_dir / collection
        if repo_dir.exists():
            shutil.rmtree(repo_dir)

        # clone tag shallow (detached HEAD for tags is fine)
        rc = run(["git", "clone", "--depth", "1", "--branch", tag, repo_url, str(repo_dir)], check=False).returncode
        if rc != 0:
            raise RuntimeError(f"git clone failed: {repo_url} (tag {tag})")

        # deps (optional/offline)
        if self.cfg.deps_mode != "none":
            deps = parse_dependencies(repo_dir)
            for dep_name, dep_constraint in deps.items():
                try:
                    self._workaround_install_one(
                        workdir=workdir,
                        offline_dir=offline_dir,
                        repos_dir=repos_dir,
                        collection=dep_name,
                        constraint=dep_constraint,
                        primary=False,
                    )
                except Exception as e:
                    if self.cfg.deps_mode == "strict":
                        raise
                    print(f"WARNING: dependency install failed for {dep_name}: {e}", file=sys.stderr)

        # build -> tarball
        rc = run(["ansible-galaxy", "collection", "build"], cwd=repo_dir, check=False).returncode
        if rc != 0:
            raise RuntimeError(f"ansible-galaxy collection build failed in {repo_dir}")

        tb = newest_tarball(repo_dir)
        dest_tb = offline_dir / tb.name
        tb.replace(dest_tb)

        # install tarball locally; always disable Galaxy dependency resolution
        cmd = ["ansible-galaxy", "collection", "install", str(dest_tb), "--no-deps", *self.passthrough_args]
        rc = run(cmd, check=False).returncode
        if rc != 0:
            raise RuntimeError(f"fallback install failed for {collection} from {dest_tb}")

    def install(self, collection: str, version: Optional[str]) -> int:
        """
        Install a collection according to configured mode.

        Args:
            collection: Collection name `namespace.collection`.
            version: Optional exact version string "X.Y.Z".

        Returns:
            0 on success; a non-zero return code if mode is "galaxy" and the Galaxy install fails.

        Raises:
            RuntimeError: If workaround installation fails (in auto/workaround mode).
        """
        if self.cfg.mode == "galaxy":
            return self.galaxy_install(collection, version)

        if self.cfg.mode == "workaround":
            self.workaround_install(collection, version)
            return 0

        # auto
        rc = self.galaxy_install(collection, version)
        if rc == 0:
            return 0

        # fallback
        self.workaround_install(collection, version)
        return 0


def build_arg_parser() -> argparse.ArgumentParser:
    """
    Build the CLI argument parser.

    Returns:
        Configured ArgumentParser that supports an initial set of flags and collects
        unknown arguments for passthrough to `ansible-galaxy`.
    """
    p = argparse.ArgumentParser(description="ansible-galaxy installer with GitHub fallback (clone/build/install tar.gz).")
    p.add_argument("collection", help="namespace.collection or namespace.collection==x.y.z")
    p.add_argument("--mode", choices=["auto", "galaxy", "workaround"], default="auto")
    p.add_argument("--version", help="Override version x.y.z (exact).")
    p.add_argument("--repo-base", default="https://github.com/ansible-collections", help="Base URL for collection repos.")
    p.add_argument("--repo-url", help="Override repo URL for the primary collection only.")
    p.add_argument("--repo-map", help="JSON/YAML mapping collection->repo_url for special cases.")
    p.add_argument("--keep-workdir", action="store_true", help="Persist workdir as .agc-workdir-<pid>.")
    p.add_argument(
        "--deps-mode",
        choices=["none", "best-effort", "strict"],
        default="best-effort",
        help="Workaround dependency handling (offline): none|best-effort|strict.",
    )
    return p


def main(argv: List[str]) -> int:
    """
    CLI entry point.

    Responsibilities:
    - Validate required external commands.
    - Parse known arguments and pass through the remaining ones to `ansible-galaxy`.
    - Validate the collection name format.
    - Load optional repository mapping.
    - Execute installation based on selected mode.

    Args:
        argv: CLI arguments (excluding program name).

    Returns:
        Process exit code: 0 on success, 1 on failure.
    """
    ensure_cmd("ansible-galaxy")
    ensure_cmd("git")

    parser = build_arg_parser()
    args, passthrough = parser.parse_known_args(argv)

    name, ver_from_spec = parse_collection_spec(args.collection)
    if not COLLECTION_RE.fullmatch(name):
        raise SystemExit(f"ERROR: collection must look like namespace.collection (got: {name})")

    version = args.version.strip().lstrip("v") if args.version else ver_from_spec
    repo_map = load_repo_map(args.repo_map)

    cfg = Config(
        mode=args.mode,
        repo_base=args.repo_base,
        repo_url_primary=args.repo_url,
        repo_map=repo_map,
        keep_workdir=bool(args.keep_workdir),
        deps_mode=args.deps_mode,
    )

    inst = Installer(cfg, passthrough)

    try:
        return inst.install(name, version)
    except Exception as e:
        print(f"ERROR: {e}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
