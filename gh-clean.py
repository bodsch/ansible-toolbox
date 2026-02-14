#!/usr/bin/env python3
"""
gh-clean.py

Command-line utility to delete GitHub Actions workflow runs and/or their logs.

The tool supports two cleanup strategies:

1) Cleanup per existing workflow (default):
   - Lists current workflows via the Workflows API.
   - For each workflow, keeps only the most recent *N* runs and deletes the rest.

2) Optional purge of orphaned runs/logs:
   - Lists all workflow runs in the repository (including runs of deleted workflow files).
   - Deletes orphaned runs/logs entirely (no keep threshold).
   - Still enforces `--keep` for runs belonging to workflows that still exist.

The script uses the GitHub REST API (v3) via `requests` and configures retries for
transient server errors on GET/DELETE requests.

Environment variables (used as defaults if CLI flags are not provided):
- GH_TOKEN: GitHub access token (PAT or GitHub Actions token)
- GH_REPOSITORY: repository in the form "owner/repo" (recommended) or repo name only (paired with GH_USERNAME)
- GH_USERNAME: repository owner (used when GH_REPOSITORY is not "owner/repo")
- GH_KEEP_WORKFLOWS: number of workflow runs to keep per workflow (default: "2")

Typical usage:
    python gh-clean.py --token "$GH_TOKEN" --repo "owner/repo" --keep 10
    python gh-clean.py --token "$GH_TOKEN" --repo "owner/repo" --keep 10 --delete-mode logs
    python gh-clean.py --token "$GH_TOKEN" --repo "owner/repo" --keep 10 --purge-orphans
"""

import argparse
import logging
import os
import sys
from typing import (
    Any,
    Dict,
    Iterable,
    List,
    Literal,
    Mapping,
    Optional,
    Set,
    Tuple,
    cast,
)

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")
logger = logging.getLogger(__name__)


class GitHubCleaner:
    """
    Cleanup helper for GitHub Actions workflow runs.

    This class deletes old workflow runs and/or their logs using GitHub's REST API.

    High-level behavior:
        - By default, cleanup is performed per *existing* workflow definition:
          only runs of workflows returned by the Workflows API are considered.
        - If `purge_orphans` is enabled, runs belonging to workflows that no longer
          exist (e.g. deleted workflow YAML files) are detected and removed entirely.

    Notes:
        - The public API is intentionally small and stable:
          `list_workflows()`, `list_all_runs(wf_id)`, and `cleanup()`.
        - Networking is performed via a shared `requests.Session` with retries
          configured for transient 5xx errors on GET and DELETE requests.

    Args:
        token: GitHub access token used for API authentication.
        repo: Repository name or "owner/repo". If "owner/repo" is provided, it takes
            precedence over `user` for owner resolution.
        user: Repository owner (only used if `repo` is not in "owner/repo" form).
        keep: Number of most recent workflow runs to keep per workflow.

    Raises:
        ValueError: If `keep` is negative.
    """

    _DEFAULT_API_BASE: str = "https://api.github.com"
    _DEFAULT_TIMEOUT_S: float = 30.0
    _API_VERSION: str = "2022-11-28"
    _PER_PAGE: int = 100

    def __init__(self, token: str, repo: str, user: str, keep: int) -> None:
        """
        Initialize a `GitHubCleaner` instance.

        Creates a dedicated HTTP session configured for GitHub's REST API, including:
        - Authorization header using the provided token
        - `Accept: application/vnd.github+json`
        - `X-GitHub-Api-Version` pinned to a stable version
        - A conservative retry strategy for transient 5xx errors on GET/DELETE
        - A default request timeout to avoid hanging indefinitely

        The repository can be provided either as "owner/repo" via `repo` or as separate
        `user` (owner) + `repo` (name). If `repo` contains a slash, it is treated as
        "owner/repo" and takes precedence over `user`.

        Runtime configuration attributes (usually set by CLI code after instantiation):
            delete_mode:
                "runs" deletes entire runs, "logs" deletes only logs for runs that are
                removed due to the keep threshold.
            purge_orphans:
                If enabled, orphaned runs/logs (without a corresponding existing workflow)
                are removed entirely (no keep threshold applied).
            orphan_delete_mode:
                "runs" deletes orphaned runs, "logs" deletes only orphaned logs.

        Args:
            token: GitHub access token used for API authentication.
            repo: Repository name or "owner/repo".
            user: Repository owner (only used if `repo` is not in "owner/repo").
            keep: Number of most recent workflow runs to keep per workflow.

        Raises:
            ValueError: If `keep` is negative.
        """
        if keep < 0:
            raise ValueError("keep must be >= 0")

        # Deletion behavior (configured via CLI by setting attributes after instantiation).
        self.delete_mode: Literal["runs", "logs"] = "runs"
        self.purge_orphans: bool = False
        self.orphan_delete_mode: Literal["runs", "logs"] = "runs"

        owner, repo_name = self._split_owner_repo(user=user, repo=repo)

        self.session: requests.Session = requests.Session()
        self.session.headers.update(
            {
                # GitHub accepts both "Bearer" and "token" for PATs; "Bearer" also works for JWTs.
                "Authorization": f"Bearer {token}",
                "Accept": "application/vnd.github+json",
                "X-GitHub-Api-Version": self._API_VERSION,
                "User-Agent": "github-cleaner",
            }
        )

        retry = Retry(
            total=5,
            connect=5,
            read=5,
            backoff_factor=0.5,
            status_forcelist=(500, 502, 503, 504),
            allowed_methods=frozenset({"GET", "DELETE"}),
            respect_retry_after_header=True,
        )
        adapter = HTTPAdapter(max_retries=retry)
        self.session.mount("https://", adapter)

        self.base: str = self._DEFAULT_API_BASE
        self.owner: str = owner
        self.repo: str = repo_name
        self.keep: int = keep
        self._timeout_s: float = self._DEFAULT_TIMEOUT_S

    @staticmethod
    def _split_owner_repo(*, user: str, repo: str) -> Tuple[str, str]:
        """
        Normalize owner/repo inputs.

        Supports both:
        - `repo="owner/repo"` (preferred; owner will be extracted from repo), or
        - `repo="repo"` + `user="owner"`.

        Args:
            user: Fallback owner name if `repo` is not "owner/repo".
            repo: Repository string, either "owner/repo" or just "repo".

        Returns:
            Tuple (owner, repo_name), both stripped of surrounding whitespace.
        """
        if "/" in repo:
            owner, repo_name = repo.split("/", 1)
            return owner.strip(), repo_name.strip()
        return user.strip(), repo.strip()

    def _request(
        self,
        method: str,
        url: str,
        *,
        params: Optional[Mapping[str, Any]] = None,
    ) -> requests.Response:
        """
        Perform an HTTP request against the GitHub API with timeout and enriched errors.

        The method uses the configured `requests.Session` (including retry logic for
        transient failures). For non-2xx responses, it raises `requests.HTTPError`
        and (if possible) includes the GitHub JSON error message for easier debugging.

        Args:
            method: HTTP method (e.g., "GET", "DELETE").
            url: Fully qualified URL to call.
            params: Optional query parameters.

        Returns:
            The `requests.Response` object (already validated via `raise_for_status()`).

        Raises:
            requests.HTTPError: For non-success responses.
        """
        resp = self.session.request(method, url, params=params, timeout=self._timeout_s)
        try:
            resp.raise_for_status()
        except requests.HTTPError as exc:
            msg: Optional[str] = None
            try:
                payload = resp.json()
                if isinstance(payload, dict):
                    raw_msg = payload.get("message")
                    if isinstance(raw_msg, str):
                        msg = raw_msg
            except ValueError:
                msg = None

            detail = f"{resp.status_code} {resp.reason}"
            if msg:
                detail = f"{detail}: {msg}"
            raise requests.HTTPError(detail, response=resp) from exc
        return resp

    def _iter_paginated(
        self,
        url: str,
        *,
        params: Optional[Mapping[str, Any]],
        items_key: str,
    ) -> Iterable[dict]:
        """
        Iterate items across GitHub-style paginated responses.

        Args:
            url: The initial URL to request.
            params: Query parameters for the initial request (e.g. `per_page`).
            items_key: JSON key that contains the list of items.

        Yields:
            Items (dict) from each page in response order.
        """
        next_url: Optional[str] = url
        next_params: Optional[Mapping[str, Any]] = params

        while next_url:
            r = self._request("GET", next_url, params=next_params)
            data: Dict[str, Any] = cast(Dict[str, Any], r.json())
            items = data.get(items_key, [])
            if isinstance(items, list):
                for item in items:
                    if isinstance(item, dict):
                        yield item

            next_url = r.links.get("next", {}).get("url")
            next_params = (
                None  # next-link is fully qualified; do not override query params
            )

    def _list_workflow_ids(self) -> Set[int]:
        """
        Return the set of workflow IDs that currently exist in the repository.

        Returns:
            A set of workflow IDs.
        """
        ids: Set[int] = set()
        for wf in self.list_workflows():
            wf_id = wf.get("id")
            if isinstance(wf_id, int):
                ids.add(wf_id)
        return ids

    def list_repo_runs(self) -> List[dict]:
        """
        List all workflow runs for the configured repository (including pagination).

        This method returns runs even if the originating workflow file no longer exists
        (i.e., orphaned runs that won't be discovered via listing current workflows).

        Returns:
            A list of workflow run objects as dictionaries, sorted by `created_at`
            in descending order (newest first).
        """
        url = f"{self.base}/repos/{self.owner}/{self.repo}/actions/runs"
        params: Mapping[str, Any] = {"per_page": self._PER_PAGE}

        runs = list(self._iter_paginated(url, params=params, items_key="workflow_runs"))
        return sorted(runs, key=lambda x: x.get("created_at", ""), reverse=True)

    def delete_run_logs(self, run_id: int) -> None:
        """
        Delete logs for a specific workflow run, keeping the run metadata.

        Args:
            run_id: The workflow run id.
        """
        url = f"{self.base}/repos/{self.owner}/{self.repo}/actions/runs/{run_id}/logs"
        try:
            self._request("DELETE", url)
        except requests.HTTPError as exc:
            # Logs may already be expired/removed; treat as non-fatal if the API says so.
            resp = getattr(exc, "response", None)
            status = getattr(resp, "status_code", None)
            if status in (404, 410):
                return
            raise

    def _delete_run(self, run_id: int) -> None:
        """
        Delete an entire workflow run (including associated logs).

        Args:
            run_id: The workflow run id.
        """
        url = f"{self.base}/repos/{self.owner}/{self.repo}/actions/runs/{run_id}"
        self._request("DELETE", url)

    def _delete_run_or_logs(self, run_id: int, mode: Literal["runs", "logs"]) -> None:
        """
        Delete either the entire run or only its logs.

        Args:
            run_id: The workflow run id.
            mode: "runs" to delete the run, "logs" to delete only logs.
        """
        if mode == "logs":
            self.delete_run_logs(run_id)
            return
        self._delete_run(run_id)

    def cleanup(self) -> None:
        """
        Delete older workflow runs, keeping only the most recent `self.keep` runs per workflow.

        Default behavior (fast path):
            Iterates over *existing* workflows and deletes runs beyond `self.keep`.

        Orphan purge behavior (optional):
            If `self.purge_orphans` is enabled, orphaned runs/logs (i.e. runs whose
            workflow no longer exists) are removed entirely (no keep threshold applied).
            Runs belonging to existing workflows are still subject to the keep threshold.

        Side effects:
            Issues DELETE requests to the GitHub API to remove workflow runs or logs.
        """
        logger.info(
            "Cleaning up workflows for %s/%s (keep=%d)",
            self.owner,
            self.repo,
            self.keep,
        )

        if not self.purge_orphans:
            # Fast path: only consider runs for workflows that currently exist.
            for wf in self.list_workflows():
                wf_id = wf.get("id")
                if not isinstance(wf_id, int):
                    continue

                wf_name = wf.get("name", "<unknown>")
                name = wf_name if isinstance(wf_name, str) else "<unknown>"

                runs = self.list_all_runs(wf_id)
                run_ids_to_delete: List[int] = []
                for run in runs[self.keep :]:
                    run_id = run.get("id")
                    if isinstance(run_id, int):
                        run_ids_to_delete.append(run_id)

                if not run_ids_to_delete:
                    continue

                logger.info(
                    " → Deleting %d runs of '%s' (mode=%s)",
                    len(run_ids_to_delete),
                    name,
                    self.delete_mode,
                )
                for run_id in run_ids_to_delete:
                    self._delete_run_or_logs(run_id, self.delete_mode)

            return

        # Full mode: detect orphaned runs via repo-wide run listing + current workflow IDs.
        existing_workflow_ids = self._list_workflow_ids()
        all_runs = self.list_repo_runs()

        active_runs: List[dict] = []
        orphan_runs: List[dict] = []

        for run in all_runs:
            wf_id = run.get("workflow_id")
            if isinstance(wf_id, int) and wf_id in existing_workflow_ids:
                active_runs.append(run)
            else:
                orphan_runs.append(run)

        if orphan_runs:
            orphan_run_ids: List[int] = []
            for run in orphan_runs:
                run_id = run.get("id")
                if isinstance(run_id, int):
                    orphan_run_ids.append(run_id)

            logger.info(
                " → Purging %d orphaned runs (mode=%s)",
                len(orphan_run_ids),
                self.orphan_delete_mode,
            )
            for run_id in orphan_run_ids:
                self._delete_run_or_logs(run_id, self.orphan_delete_mode)

        # Enforce keep for runs of existing workflows.
        groups: Dict[int, List[dict]] = {}
        for run in active_runs:
            wf_id = run.get("workflow_id")
            if isinstance(wf_id, int):
                groups.setdefault(wf_id, []).append(run)

        for wf_id, runs in groups.items():
            run_ids_to_delete: List[int] = []
            for run in runs[self.keep :]:
                run_id = run.get("id")
                if isinstance(run_id, int):
                    run_ids_to_delete.append(run_id)

            if not run_ids_to_delete:
                continue

            logger.info(
                " → Deleting %d runs of workflow_id=%d (mode=%s)",
                len(run_ids_to_delete),
                wf_id,
                self.delete_mode,
            )
            for run_id in run_ids_to_delete:
                self._delete_run_or_logs(run_id, self.delete_mode)

    def list_workflows(self) -> List[dict]:
        """
        List GitHub Actions workflows for the configured repository.

        Returns:
            A list of workflow objects as dictionaries as returned by the GitHub API.
            The content is intentionally untyped (`dict`) to keep the public API stable.
        """
        url = f"{self.base}/repos/{self.owner}/{self.repo}/actions/workflows"
        resp = self._request("GET", url)
        payload: Dict[str, Any] = cast(Dict[str, Any], resp.json())
        workflows = payload.get("workflows", [])
        return cast(List[dict], workflows)

    def list_all_runs(self, wf_id: int) -> List[dict]:
        """
        Fetch all runs for a given workflow id, including pagination.

        The returned list is sorted by `created_at` in descending order (newest first).

        Args:
            wf_id: Workflow id as provided by `list_workflows()` (workflow["id"]).

        Returns:
            A list of workflow run objects as dictionaries.
        """
        url = (
            f"{self.base}/repos/{self.owner}/{self.repo}/actions/workflows/{wf_id}/runs"
        )
        params: Mapping[str, Any] = {"per_page": self._PER_PAGE}

        runs = list(self._iter_paginated(url, params=params, items_key="workflow_runs"))
        return sorted(runs, key=lambda x: x.get("created_at", ""), reverse=True)


def main() -> None:
    """
    CLI entry point.

    Parses command-line arguments (with environment variable defaults), validates
    required inputs, configures cleanup behavior and executes cleanup.

    Exit codes:
        0: Success
        1: Missing required parameters
    """
    parser = argparse.ArgumentParser(description="Cleanup old GitHub Actions runs/logs")
    parser.add_argument(
        "--token",
        default=os.getenv("GH_TOKEN"),
        help="GitHub access token (or GH_TOKEN)",
    )
    parser.add_argument(
        "--repo",
        default=os.getenv("GH_REPOSITORY"),
        help="Repository, e.g. 'org/repo' (or GH_REPOSITORY)",
    )
    parser.add_argument(
        "--user",
        default=os.getenv("GH_USERNAME"),
        help="Repository owner (or GH_USERNAME)",
    )
    parser.add_argument(
        "--keep",
        type=int,
        default=int(os.getenv("GH_KEEP_WORKFLOWS", "2")),
        help="Runs to keep per workflow (or GH_KEEP_WORKFLOWS)",
    )

    parser.add_argument(
        "--delete-mode",
        choices=("runs", "logs"),
        default="runs",
        help="What to delete for runs exceeding --keep: 'runs' deletes entire runs, 'logs' deletes only logs.",
    )

    parser.add_argument(
        "--purge-orphans",
        action="store_true",
        help="Additionally remove orphaned runs/logs (runs whose workflow file no longer exists).",
    )

    parser.add_argument(
        "--orphan-delete-mode",
        choices=("runs", "logs"),
        default="runs",
        help="What to delete for orphaned runs: 'runs' deletes entire runs, 'logs' deletes only logs.",
    )

    args = parser.parse_args()

    missing: List[str] = []
    if not args.token:
        missing.append("TOKEN")
    if not args.repo:
        missing.append("REPO")

    # `user` is only required when repo is not given as "owner/repo".
    if args.repo and "/" not in args.repo and not args.user:
        missing.append("USER")

    if missing:
        logger.error("Missing required parameter(s): %s", ", ".join(missing))
        sys.exit(1)

    cleaner = GitHubCleaner(
        token=args.token, repo=args.repo, user=args.user or "", keep=args.keep
    )
    cleaner.delete_mode = cast(Literal["runs", "logs"], args.delete_mode)
    cleaner.purge_orphans = bool(args.purge_orphans)
    cleaner.orphan_delete_mode = cast(Literal["runs", "logs"], args.orphan_delete_mode)
    cleaner.cleanup()


if __name__ == "__main__":
    main()
