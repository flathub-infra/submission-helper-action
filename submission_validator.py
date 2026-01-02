#!/usr/bin/env python3

import json
import logging
import os
import re
import subprocess
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Any, NamedTuple

from publicsuffixlist import PublicSuffixList  # type: ignore[import-untyped]

logging.basicConfig(level=logging.INFO, format="%(levelname)s - %(message)s")
logger = logging.getLogger(__name__)

ADD_PREFIX_RE = re.compile(r"^add\s+", re.IGNORECASE)


class ValidationResult(NamedTuple):
    is_valid: bool
    reasons: list[str]
    domain: str | None = None


def get_appid_from_pr_title(title: str) -> str | None:
    matched = ADD_PREFIX_RE.match(title)
    if not matched:
        return None

    appid = title[matched.end() :].strip()
    parts = appid.split(".")

    if not (3 <= len(parts) <= 255):
        return None

    appid_cpt_re = re.compile(r"^[A-Za-z_][\w-]*$")

    if not all(appid_cpt_re.fullmatch(p) for p in parts):
        return None

    return appid


def extract_domain_from_appid(appid: str) -> str | None:
    addon_cpt = (
        "addon",
        "addons",
        "extension",
        "extensions",
        "plugin",
        "plugins",
    )

    excluded_id_prefix = (
        "com.github.",
        "com.gitlab.",
        "io.github.",
        "io.gitlab.",
        "org.gnome.gitlab.",
        "org.gnome.World.",
        "org.gnome.design",
        "org.kde.",
        "org.gnome.",
    )

    runtime_prefix = (
        "org.freedesktop.Platform.",
        "org.freedesktop.Sdk.",
        "org.gnome.Platform.",
        "org.gnome.Sdk.",
        "org.gtk.Gtk3theme.",
        "org.kde.KStyle.",
        "org.kde.Platform.",
        "org.kde.PlatformInputContexts.",
        "org.kde.PlatformTheme.",
        "org.kde.Sdk.",
        "org.kde.WaylandDecoration.",
    )

    code_host_prefix = (
        "io.frama.",
        "page.codeberg.",
        "io.sourceforge.",
        "net.sourceforge.",
    )

    def demangle_name(name: str) -> str:
        if name.startswith("_") and len(name) > 1 and name[1].isdigit():
            name = name[1:]
        return name.replace("_", "-")

    if appid.count(".") < 2:
        return None

    parts = appid.split(".")

    if (
        appid.startswith(excluded_id_prefix)
        or appid.endswith(".BaseApp")
        or parts[-2].lower() in addon_cpt
        or appid.startswith(runtime_prefix)
    ):
        return None

    if appid.startswith(code_host_prefix):
        tld, domain, name = appid.split(".")[:3]
        name = demangle_name(name)
        if domain == "sourceforge":
            return f"{name}.{domain}.io".lower()
        return f"{name}.{domain}.{tld}".lower()

    fqdn = ".".join(reversed(appid.split("."))).lower()
    psl = PublicSuffixList()

    if psl.is_private(fqdn):
        return demangle_name(psl.privatesuffix(fqdn))

    parts = [demangle_name(p) for p in appid.split(".")[:-1]]
    return ".".join(reversed(parts)).lower()


@dataclass(frozen=True)
class PR:
    number: int
    title: str
    body: str
    is_draft: bool
    files: list[str]
    comments: str
    labels: set[str]
    has_master_commit: bool = False


class PRValidator:
    MAX_FAILED_BUILDS_BEFORE_LOCK = 5

    def __init__(self) -> None:
        self.gh_repo = os.environ["GITHUB_REPOSITORY"]
        self.base_review_comment = (
            "This pull request is temporarily marked as blocked as some "
            "automated checks failed on it. Please make sure the "
            "following items are done:"
        )
        self.build_start_comment = (
            "Starting a test build of the submission. Please fix any "
            "issues reported in the build log. You can restart the build "
            "once the issue is fixed by commenting the phrase below.\n\n"
            "bot, build"
        )
        self.locked_comment = (
            "This pull request is marked as blocked and has too many "
            "failing builds. Locking this PR temporarily. Please build "
            "it locally following the instructions and push the relevant "
            "changes first."
        )
        self.domain_comment_partial = "The domain to be used for verification is"
        self.build_success_comment = "[Test build succeeded]"
        self.build_start_comment_partial = "Starting a test build of the submission"
        self.required_checklist_item = (
            "I have read and followed all the [Submission requirements]"
        )

    def run(self, cmd: list[str]) -> subprocess.CompletedProcess[str]:
        env = os.environ.copy()
        env["GH_REPO"] = self.gh_repo
        return subprocess.run(
            cmd,
            check=False,
            capture_output=True,
            text=True,
            env=env,
        )

    def fetch_pr_data(self, pr_num: int) -> dict[str, Any]:
        cmd = [
            "gh",
            "pr",
            "view",
            str(pr_num),
            "--json",
            "title,body,isDraft,files,comments,labels,commits",
        ]

        result = self.run(cmd)
        if result.returncode != 0:
            logger.error(
                "Failed to fetch PR #%s data. Return code: %s, stderr: %s",
                pr_num,
                result.returncode,
                result.stderr.strip(),
            )
            return {}

        try:
            pr_data: dict[str, Any] = json.loads(result.stdout)
            return pr_data
        except json.JSONDecodeError as e:
            logger.error(
                "Failed to parse JSON for PR #%s: %s. stdout: %s",
                pr_num,
                e,
                result.stdout[:200],
            )
            return {}

    def parse_pr_from_data(self, data: dict[str, Any], pr_num: int) -> PR:
        comments = "\n".join(
            c.get("body", "")
            for c in data.get("comments", [])
            if c.get("author", {}).get("login") in ("flathubbot", "github-actions")
        )

        commits = data.get("commits", [])
        has_master_commit = any(
            commit.get("messageHeadline") == "Add some instructions"
            and any(
                author.get("email") == "mclasen@redhat.com"
                for author in commit.get("authors", [])
            )
            for commit in commits
        )

        return PR(
            number=pr_num,
            title=data.get("title", ""),
            body=data.get("body", "").replace("\r", ""),
            is_draft=bool(data.get("isDraft", False)),
            files=[f["path"] for f in data.get("files", []) if "path" in f],
            comments=comments,
            labels={label["name"] for label in data.get("labels", [])},
            has_master_commit=has_master_commit,
        )

    def fetch_recent_prs(
        self, cutoff: str, is_draft: bool, now: datetime | None = None
    ) -> list[int]:
        cmd = [
            "gh",
            "pr",
            "list",
            "--base",
            "new-pr",
            "-L",
            "50",
            "--state",
            "open",
            "--json",
            "number,createdAt,updatedAt,isDraft,labels",
        ]

        result = self.run(cmd)
        if result.returncode != 0:
            logger.error(
                "Failed to fetch PR list. Return code: %s, stderr: %s",
                result.returncode,
                result.stderr.strip(),
            )
            return []

        try:
            prs = json.loads(result.stdout)
        except json.JSONDecodeError as e:
            logger.error("Failed to parse PR list JSON: %s", e)
            return []

        cutoff_dt = datetime.fromisoformat(cutoff.replace("Z", "+00:00"))
        now = now or datetime.now().astimezone()
        recent = now - timedelta(days=2)

        def valid(pr: dict[str, Any]) -> bool:
            labels = {label["name"] for label in pr.get("labels", [])}
            return (
                pr["isDraft"] == is_draft
                and datetime.fromisoformat(pr["createdAt"].replace("Z", "+00:00"))
                >= cutoff_dt
                and datetime.fromisoformat(pr["updatedAt"].replace("Z", "+00:00"))
                >= recent
                and "Stale" not in labels
            )

        filtered_prs = [pr["number"] for pr in prs if valid(pr)][:30]
        logger.info(
            "Found %s %s PRs matching criteria",
            len(filtered_prs),
            "draft" if is_draft else "non-draft",
        )
        return filtered_prs

    def validate_pr_structure(self, pr: PR) -> ValidationResult:
        reasons = []

        appid = get_appid_from_pr_title(pr.title)
        if not appid:
            reasons.append('- PR title is "Add $FLATPAK_ID"')
            logger.info("PR #%s: Invalid or missing app ID in title", pr.number)

        if pr.has_master_commit:
            branch_link = f"https://github.com/{self.gh_repo}/commits/master/"
            reasons.append(
                f"- PR does not contain commits from the [master branch]({branch_link})"
            )
            logger.info("PR #%s: Contains master branch commits", pr.number)

        flathub_json_re = re.compile(r".*/flathub\.json$")
        if any(flathub_json_re.search(f) for f in pr.files):
            reasons.append("- flathub.json file is at toplevel")
            logger.info("PR #%s: flathub.json not at toplevel", pr.number)

        toplevel_manifest_re = re.compile(r"^(?!flathub\.json$)[^/]+\.(ya?ml|json)$")
        if not any(toplevel_manifest_re.match(f) for f in pr.files):
            reasons.append("- Flatpak manifest is at toplevel")
            logger.info("PR #%s: Manifest not at toplevel", pr.number)

        checked_re = re.compile(r"^- ?\[[xX]\] ", re.MULTILINE)
        unchecked_re = re.compile(r"^- \[ \] ", re.MULTILINE)

        checked = len(checked_re.findall(pr.body))
        unchecked = len(unchecked_re.findall(pr.body))

        if checked == 0 or unchecked > 0:
            checklist_link = f"https://github.com/{self.gh_repo}/blob/master/.github/pull_request_template.md?plain=1)"
            reasons.append(
                f"- All [checklists]({checklist_link}) are present in PR "
                "body and are completed"
            )
            logger.info(
                "PR #%s: Incomplete checklist (checked: %s, unchecked: %s)",
                pr.number,
                checked,
                unchecked,
            )

        if self.required_checklist_item.lower() not in pr.body.lower():
            reasons.append("- Required checklist item not found")
            logger.info("PR #%s: Missing required checklist item", pr.number)

        domain = extract_domain_from_appid(appid) if appid else None

        if reasons:
            logger.info(
                "PR #%s validation failed with %s issue(s)", pr.number, len(reasons)
            )
        else:
            logger.info("PR #%s validation passed", pr.number)

        return ValidationResult(
            is_valid=len(reasons) == 0, reasons=reasons, domain=domain
        )

    def update_pr_labels(
        self, pr: PR, labels_to_add: set[str], labels_to_remove: set[str]
    ) -> None:
        if not labels_to_add and not labels_to_remove:
            return

        logger.info(
            "Updating labels for PR #%s: adding %s, removing %s",
            pr.number,
            labels_to_add,
            labels_to_remove,
        )

        cmd = ["gh", "pr", "edit", str(pr.number)]

        if labels_to_add:
            cmd.extend(["--add-label", ",".join(sorted(labels_to_add))])
        if labels_to_remove:
            cmd.extend(["--remove-label", ",".join(sorted(labels_to_remove))])

        result = self.run(cmd)
        if result.returncode != 0:
            logger.error(
                "Failed to update labels for PR #%s. Return code: %s, stderr: %s",
                pr.number,
                result.returncode,
                result.stderr.strip(),
            )

    def add_comment(self, pr: PR, body: str) -> None:
        result = self.run(["gh", "pr", "comment", str(pr.number), "--body", body])
        if result.returncode != 0:
            logger.error(
                "Failed to add comment to PR #%s. Return code: %s, stderr: %s",
                pr.number,
                result.returncode,
                result.stderr.strip(),
            )

    def lock_pr(self, pr: PR) -> None:
        result = self.run(["gh", "pr", "lock", str(pr.number)])
        if result.returncode != 0:
            logger.error(
                "Failed to lock PR #%s. Return code: %s, stderr: %s",
                pr.number,
                result.returncode,
                result.stderr.strip(),
            )

    def get_unresolved_review_threads(self, pr_num: int) -> int:
        query = """
        query($owner: String!, $repo: String!, $number: Int!) {
          repository(owner: $owner, name: $repo) {
            pullRequest(number: $number) {
              reviewThreads(first: 100) {
                nodes {
                  isResolved
                }
              }
            }
          }
        }
        """

        owner, repo = self.gh_repo.split("/", 1)

        cmd = [
            "gh",
            "api",
            "graphql",
            "-f",
            f"query={query}",
            "-F",
            f"owner={owner}",
            "-F",
            f"repo={repo}",
            "-F",
            f"number={pr_num}",
        ]

        result = self.run(cmd)
        if result.returncode != 0:
            logger.error(
                "Failed to fetch review threads for PR #%s. Exit code: %s, stderr: %s",
                pr_num,
                result.returncode,
                result.stderr.strip(),
            )
            return 0

        try:
            data = json.loads(result.stdout)
            threads = data["data"]["repository"]["pullRequest"]["reviewThreads"][
                "nodes"
            ]
            unresolved = sum(1 for t in threads if not t["isResolved"])
            logger.info("PR #%s has %s unresolved review threads", pr_num, unresolved)
            return unresolved
        except (KeyError, TypeError, json.JSONDecodeError) as e:
            logger.error(
                "Failed to parse review threads for PR #%s: %s. stdout: %s",
                pr_num,
                e,
                result.stdout[:200],
            )
            return 0

    def should_start_build(self, pr: PR) -> bool:
        return not any(
            c in pr.comments
            for c in (self.build_start_comment_partial, self.build_success_comment)
        )

    def should_lock_pr(self, pr: PR) -> bool:
        if not {"pr-check-blocked", "blocked"} & pr.labels:
            return False

        if self.build_success_comment in pr.comments:
            return False

        failed_builds = len(
            re.findall(r"Test build.*failed", pr.comments, re.IGNORECASE)
        )

        logger.info(
            "PR #%s has %s failed builds (threshold: %s)",
            pr.number,
            failed_builds,
            self.MAX_FAILED_BUILDS_BEFORE_LOCK,
        )

        return failed_builds > self.MAX_FAILED_BUILDS_BEFORE_LOCK

    def process_pr_validation(self, pr: PR, validation: ValidationResult) -> None:
        labels_to_add = set()
        labels_to_remove = set()

        if not validation.is_valid:
            labels_to_add.add("pr-check-blocked")
            labels_to_remove.add("awaiting-review")

            if self.base_review_comment not in pr.comments:
                req_doc_link = (
                    "https://docs.flathub.org/docs/for-app-authors/requirements"
                )
                subm_doc_link = (
                    "https://docs.flathub.org/docs/for-app-authors/submission"
                )
                last_reason = (
                    f"The [requirements]({req_doc_link}) and "
                    f"[submission process]({subm_doc_link}) "
                    "have been followed"
                )
                all_reasons = [*validation.reasons, last_reason]
                self.add_comment(
                    pr,
                    self.base_review_comment + "\n" + "\n".join(all_reasons),
                )
        else:
            labels_to_remove.add("pr-check-blocked")

            if not any(
                label in pr.labels
                for label in (
                    "awaiting-changes",
                    "awaiting-upstream",
                    "blocked",
                    "reviewed-waiting",
                )
            ):
                labels_to_add.add("awaiting-review")

            if "blocked" not in pr.labels and validation.domain:
                verif_url = f"https://{validation.domain}/.well-known/org.flathub.VerifiedApps.txt"
                if verif_url not in pr.comments:
                    verif_comment = (
                        f"{self.domain_comment_partial} {validation.domain}. "
                        "If you intend to [verify]"
                        "(https://docs.flathub.org/docs/for-app-authors/verification) "
                        "this submission, please confirm by uploading an empty "
                        "`org.flathub.VerifiedApps.txt` file to "
                        f"{verif_url}. Otherwise, ignore this. "
                        "Please comment if this incorrect."
                    )
                    self.add_comment(pr, verif_comment)

            if self.should_start_build(pr):
                self.add_comment(pr, self.build_start_comment)

        if labels_to_add or labels_to_remove:
            self.update_pr_labels(pr, labels_to_add, labels_to_remove)

    def update_review_state(self, pr: PR, thread_count: int) -> None:
        labels_to_add = set()
        labels_to_remove = set()

        if "awaiting-review" in pr.labels and thread_count > 0:
            labels_to_add.add("awaiting-changes")
            labels_to_remove.add("awaiting-review")
        elif (
            "awaiting-changes" in pr.labels
            and "awaiting-upstream" not in pr.labels
            and thread_count == 0
        ):
            labels_to_add.add("awaiting-review")
            labels_to_remove.add("awaiting-changes")

        if labels_to_add or labels_to_remove:
            self.update_pr_labels(pr, labels_to_add, labels_to_remove)

    def validate_pr(self, pr_num: int) -> None:
        data = self.fetch_pr_data(pr_num)
        if not data:
            logger.error("Failed to fetch data for PR #%s, skipping validation", pr_num)
            return

        pr = self.parse_pr_from_data(data, pr_num)

        validation = self.validate_pr_structure(pr)

        self.process_pr_validation(pr, validation)

        thread_count = self.get_unresolved_review_threads(pr.number)
        self.update_review_state(pr, thread_count)

        if self.should_lock_pr(pr):
            logger.info(
                "PR #%s is blocked with %s+ failing builds. Locking.",
                pr.number,
                self.MAX_FAILED_BUILDS_BEFORE_LOCK,
            )
            self.add_comment(pr, self.locked_comment)
            self.lock_pr(pr)

    def run_all(self) -> None:
        cutoff = "2025-05-25T00:00:00Z"

        prs = self.fetch_recent_prs(cutoff, is_draft=False)
        drafts = self.fetch_recent_prs(cutoff, is_draft=True)

        for pr_num in drafts:
            logger.info(
                "Processing PR https://github.com/%s/pull/%s", self.gh_repo, pr_num
            )
            self.update_pr_labels(
                PR(pr_num, "", "", True, [], "", set()), {"work-in-progress"}, set()
            )

        for pr_num in prs:
            logger.info(
                "Processing PR https://github.com/%s/pull/%s", self.gh_repo, pr_num
            )
            self.validate_pr(pr_num)


def main() -> None:
    return PRValidator().run_all()


if __name__ == "__main__":
    main()
