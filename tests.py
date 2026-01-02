import json
from datetime import datetime, timedelta, timezone
from typing import Any
from unittest.mock import Mock, patch

import pytest

from submission_validator import (
    PR,
    PRValidator,
    ValidationResult,
    extract_domain_from_appid,
    get_appid_from_pr_title,
)

SAMPLE_PR_DATA: dict[str, Any] = {
    "body": "Foobar",
    "comments": [
        {
            "id": "IC_kwDOBUvmZs7bwM_1",
            "author": {"login": "github-actions"},
            "authorAssociation": "NONE",
            "body": "A comment",
            "createdAt": "2025-12-23T14:28:19Z",
            "includesCreatedEdit": False,
            "isMinimized": False,
            "minimizedReason": "",
            "reactionGroups": [],
            "url": "https://github.com/flathub/flathub/pull/7378#issuecomment-3686846453",
            "viewerDidAuthor": False,
        }
    ],
    "commits": [
        {
            "authoredDate": "2017-04-04T10:07:32Z",
            "authors": [
                {
                    "email": "mclasen@redhat.com",
                    "id": "MDQ6VXNlcjQ4MzQ4NDU=",
                    "login": "matthiasclasen",
                    "name": "Matthias Clasen",
                }
            ],
            "committedDate": "2017-04-04T10:07:32Z",
            "messageBody": "",
            "messageHeadline": "Initial commit",
            "oid": "afa86eb08bbf99064f613e7d255393012575c101",
        },
        {
            "authoredDate": "2017-04-04T10:16:07Z",
            "authors": [
                {
                    "email": "mclasen@redhat.com",
                    "id": "MDQ6VXNlcjQ4MzQ4NDU=",
                    "login": "matthiasclasen",
                    "name": "Matthias Clasen",
                }
            ],
            "committedDate": "2017-04-04T10:16:07Z",
            "messageBody": "",
            "messageHeadline": "Add some instructions",
            "oid": "9f723058d07ae6006988914032e96be96673fc40",
        },
        {
            "authoredDate": "2025-12-23T00:06:52Z",
            "authors": [
                {
                    "email": "foobar@example.org",
                    "id": "MDQ6VXNlcjE5MTEwMjk=",
                    "login": "foobar",
                    "name": "foobar",
                }
            ],
            "committedDate": "2025-12-23T17:49:52Z",
            "messageBody": "A foobar commit body",
            "messageHeadline": "A foobar commit headline",
            "oid": "069e278ee1ba1ea131f8c1f2a68dc323459f82ed",
        },
    ],
    "files": [
        {
            "path": ".github/workflows/update_sources.yaml",
            "additions": 44,
            "deletions": 0,
        },
        {"path": "com.example.foobar.json", "additions": 68, "deletions": 0},
        {
            "path": "cargo-sources.json",
            "additions": 8416,
            "deletions": 0,
        },
    ],
    "isDraft": False,
    "labels": [
        {
            "id": "MDU6TGFiZWw2OTM2NTg2NTc=",
            "name": "ready",
            "description": "Pull request ready for final review and merge",
            "color": "0e8a16",
        }
    ],
    "title": "Add com.example.foobar",
}

SAMPLE_RECENT_PRS: list[dict[str, Any]] = [
    {
        "createdAt": "2025-12-26T23:49:00Z",
        "isDraft": False,
        "labels": [
            {
                "id": "MDU6TGFiZWw2OTM2NTgxODI=",
                "name": "awaiting-changes",
                "description": "Pull request waiting for inputs or changes from author",
                "color": "fbca04",
            },
            {
                "id": "MDU6TGFiZWw2OTM2NTg1Mjc=",
                "name": "blocked",
                "description": "Pull requests marked as blocked by reviewers",
                "color": "B60205",
            },
        ],
        "number": 7408,
        "updatedAt": "2025-12-27T14:44:12Z",
    },
    {
        "createdAt": "2025-12-26T14:35:12Z",
        "isDraft": False,
        "labels": [
            {
                "id": "MDU6TGFiZWw2OTM2NTgxODI=",
                "name": "awaiting-changes",
                "description": "Pull request waiting for inputs or changes from author",
                "color": "fbca04",
            },
            {
                "id": "MDU6TGFiZWw2OTM2NTg1Mjc=",
                "name": "blocked",
                "description": "Pull requests marked as blocked by reviewers",
                "color": "B60205",
            },
            {
                "id": "LA_kwDOBUvmZs8AAAACBWpCCA",
                "name": "pr-check-blocked",
                "description": "Pull requests marked as blocked by automation",
                "color": "B60205",
            },
        ],
        "number": 7406,
        "updatedAt": "2025-12-27T14:25:10Z",
    },
    {
        "createdAt": "2025-12-26T13:58:22Z",
        "isDraft": False,
        "labels": [
            {
                "id": "MDU6TGFiZWwxNzA4MDA2NzU4",
                "name": "migrate-app-id",
                "description": "Migrate an application to a new app-id",
                "color": "e8c296",
            },
            {
                "id": "LA_kwDOBUvmZs8AAAACBNZRsg",
                "name": "awaiting-review",
                "description": "Pull requests waiting for review",
                "color": "1d76db",
            },
        ],
        "number": 7405,
        "updatedAt": "2025-12-27T14:25:50Z",
    },
    {
        "createdAt": "2025-12-26T10:05:48Z",
        "isDraft": False,
        "labels": [
            {
                "id": "LA_kwDOBUvmZs8AAAACBWpCCA",
                "name": "pr-check-blocked",
                "description": "Pull requests marked as blocked by automation",
                "color": "B60205",
            }
        ],
        "number": 7403,
        "updatedAt": "2025-12-27T14:25:23Z",
    },
    {
        "createdAt": "2025-12-26T08:40:03Z",
        "isDraft": False,
        "labels": [
            {
                "id": "LA_kwDOBUvmZs8AAAACBNZRsg",
                "name": "awaiting-review",
                "description": "Pull requests waiting for review",
                "color": "1d76db",
            }
        ],
        "number": 7402,
        "updatedAt": "2025-12-27T14:25:29Z",
    },
]


class TestGetAppidFromPrTitle:
    def test_valid_pr_title(self):
        assert get_appid_from_pr_title("Add com.example.app") == "com.example.app"
        assert get_appid_from_pr_title("add com.example.app") == "com.example.app"

    def test_invalid_pr_title(self):
        assert get_appid_from_pr_title("Add com.App") is None
        assert get_appid_from_pr_title("Add App") is None
        assert get_appid_from_pr_title("foo bar baz") is None
        assert get_appid_from_pr_title("") is None
        assert get_appid_from_pr_title("Add ") is None


class TestExtractDomainFromAppid:
    def test_domain(self):
        assert extract_domain_from_appid("org.example.MyApp") == "example.org"

    def test_domain_excluded(self):
        assert extract_domain_from_appid("io.github.user.app") is None
        assert extract_domain_from_appid("io.gitlab.user.App") is None
        assert extract_domain_from_appid("org.gnome.app") is None
        assert extract_domain_from_appid("org.gnome.gitlab.user.app") is None
        assert extract_domain_from_appid("org.kde.app") is None
        assert extract_domain_from_appid("com.example.BaseApp") is None
        assert extract_domain_from_appid("com.example.addon.MyAddon") is None
        assert extract_domain_from_appid("com.example.addons.MyAddon") is None
        assert extract_domain_from_appid("com.example.extension.MyExt") is None
        assert extract_domain_from_appid("com.example.extensions.MyExt") is None
        assert extract_domain_from_appid("com.example.plugin.MyPlugin") is None
        assert extract_domain_from_appid("com.example.plugins.MyPlugin") is None

        assert extract_domain_from_appid("org.freedesktop.Platform.GL") is None
        assert extract_domain_from_appid("org.gnome.Platform.Locale") is None

    def test_domain_codehost(self):
        assert (
            extract_domain_from_appid("io.sourceforge.MyApp") == "myapp.sourceforge.io"
        )
        assert (
            extract_domain_from_appid("net.sourceforge.MyApp") == "myapp.sourceforge.io"
        )
        assert (
            extract_domain_from_appid("page.codeberg.user.App") == "user.codeberg.page"
        )
        assert extract_domain_from_appid("io.frama.user.App") == "user.frama.io"

    def test_domain_demangle(self):
        assert (
            extract_domain_from_appid("io.sourceforge._3DApp") == "3dapp.sourceforge.io"
        )

    def test_domain_invalid_appid(self):
        assert extract_domain_from_appid("com.App") is None


class TestPRValidator:
    @pytest.fixture
    def validator(self):
        with patch.dict("os.environ", {"GITHUB_REPOSITORY": "flathub/flathub"}):
            return PRValidator()

    @pytest.fixture
    def mock_pr(self):
        return PR(
            number=123,
            title="Add com.example.App",
            body="- [x] I have read and followed all the [Submission requirements]",
            is_draft=False,
            files=["com.example.App.yaml", "flathub.json"],
            comments="",
            labels=set(),
            has_master_commit=False,
        )

    def test_validate_pr_structure_valid(self, validator, mock_pr):
        result = validator.validate_pr_structure(mock_pr)
        assert result.is_valid
        assert len(result.reasons) == 0
        assert result.domain == "example.com"

    def test_validate_pr_structure_invalid_title(self, validator):
        pr = PR(
            number=123,
            title="Invalid Title",
            body="- [x] I have read and followed all the [Submission requirements]",
            is_draft=False,
            files=["manifest.yaml"],
            comments="",
            labels=set(),
            has_master_commit=False,
        )
        result = validator.validate_pr_structure(pr)
        assert not result.is_valid
        assert any("PR title" in reason for reason in result.reasons)

    def test_validate_pr_structure_master_commit(self, validator):
        pr = PR(
            number=123,
            title="Add com.example.App",
            body="- [x] I have read and followed all the [Submission requirements]",
            is_draft=False,
            files=["manifest.yaml"],
            comments="",
            labels=set(),
            has_master_commit=True,
        )
        result = validator.validate_pr_structure(pr)
        assert not result.is_valid
        assert any("master branch" in reason for reason in result.reasons)

    def test_validate_pr_structure_flathub_json_not_toplevel(self, validator):
        pr = PR(
            number=123,
            title="Add com.example.App",
            body="- [x] I have read and followed all the [Submission requirements]",
            is_draft=False,
            files=["manifest.yaml", "subdir/flathub.json"],
            comments="",
            labels=set(),
            has_master_commit=False,
        )
        result = validator.validate_pr_structure(pr)
        assert not result.is_valid
        assert any(
            "flathub.json file is at toplevel" in reason for reason in result.reasons
        )

    def test_validate_pr_structure_no_toplevel_manifest(self, validator):
        pr = PR(
            number=123,
            title="Add com.example.App",
            body="- [x] I have read and followed all the [Submission requirements]",
            is_draft=False,
            files=["subdir/manifest.yaml", "flathub.json"],
            comments="",
            labels=set(),
            has_master_commit=False,
        )
        result = validator.validate_pr_structure(pr)
        assert not result.is_valid
        assert any(
            "Flatpak manifest is at toplevel" in reason for reason in result.reasons
        )

    def test_validate_pr_structure_incomplete_checklist(self, validator):
        pr = PR(
            number=123,
            title="Add com.example.App",
            body="- [ ] Unchecked item\n- [x] I have read and followed all the [Submission requirements]",
            is_draft=False,
            files=["manifest.yaml"],
            comments="",
            labels=set(),
            has_master_commit=False,
        )
        result = validator.validate_pr_structure(pr)
        assert not result.is_valid
        assert any("checklists" in reason for reason in result.reasons)

    def test_validate_pr_structure_missing_required_checklist(self, validator):
        pr = PR(
            number=123,
            title="Add com.example.App",
            body="- [x] Some other item",
            is_draft=False,
            files=["manifest.yaml"],
            comments="",
            labels=set(),
            has_master_commit=False,
        )
        result = validator.validate_pr_structure(pr)
        assert not result.is_valid
        assert any(
            "Required checklist item not found" in reason for reason in result.reasons
        )

    def test_should_start_build_no_previous_build(self, validator, mock_pr):
        assert validator.should_start_build(mock_pr)

    def test_should_start_build_build_already_started(self, validator, mock_pr):
        pr = PR(
            number=mock_pr.number,
            title=mock_pr.title,
            body=mock_pr.body,
            is_draft=mock_pr.is_draft,
            files=mock_pr.files,
            comments="Starting a test build of the submission",
            labels=mock_pr.labels,
        )
        assert not validator.should_start_build(pr)

    def test_should_start_build_build_succeeded(self, validator, mock_pr):
        pr = PR(
            number=mock_pr.number,
            title=mock_pr.title,
            body=mock_pr.body,
            is_draft=mock_pr.is_draft,
            files=mock_pr.files,
            comments="[Test build succeeded]",
            labels=mock_pr.labels,
        )
        assert not validator.should_start_build(pr)

    def test_should_lock_pr_build_succeeded(self, validator, mock_pr):
        pr = PR(
            number=mock_pr.number,
            title=mock_pr.title,
            body=mock_pr.body,
            is_draft=mock_pr.is_draft,
            files=mock_pr.files,
            comments="[Test build succeeded]",
            labels={"pr-check-blocked"},
        )
        assert not validator.should_lock_pr(pr)

    def test_should_lock_pr_too_many_failures(self, validator, mock_pr):
        pr = PR(
            number=mock_pr.number,
            title=mock_pr.title,
            body=mock_pr.body,
            is_draft=mock_pr.is_draft,
            files=mock_pr.files,
            comments="\n".join(["Test build failed"] * 6),
            labels={"pr-check-blocked"},
        )
        assert validator.should_lock_pr(pr)

    def test_should_lock_pr_at_threshold(self, validator, mock_pr):
        pr = PR(
            number=mock_pr.number,
            title=mock_pr.title,
            body=mock_pr.body,
            is_draft=mock_pr.is_draft,
            files=mock_pr.files,
            comments="\n".join(["Test build failed"] * 5),
            labels={"blocked"},
        )
        assert not validator.should_lock_pr(pr)

    def test_parse_pr_from_data(self, validator):
        PR_DATA_WITHOUT_MASTER = {
            **SAMPLE_PR_DATA,
            "commits": SAMPLE_PR_DATA["commits"][2:],
        }

        pr = validator.parse_pr_from_data(PR_DATA_WITHOUT_MASTER, 123)

        assert pr.number == 123
        assert pr.title == "Add com.example.foobar"
        assert pr.body == "Foobar"
        assert pr.is_draft is False
        assert pr.files == [
            ".github/workflows/update_sources.yaml",
            "com.example.foobar.json",
            "cargo-sources.json",
        ]
        assert pr.comments == "A comment"
        assert pr.labels == {"ready"}
        assert pr.has_master_commit is False

    def test_parse_pr_from_data_with_master_commit(self, validator):
        pr = validator.parse_pr_from_data(SAMPLE_PR_DATA, 123)
        assert pr.has_master_commit is True

    def test_fetch_pr_data_success(self, validator):
        mock_result = Mock()
        mock_result.returncode = 0
        mock_result.stdout = json.dumps(SAMPLE_PR_DATA)

        with patch.object(validator, "run", return_value=mock_result):
            data = validator.fetch_pr_data(123)

        assert data["title"] == "Add com.example.foobar"

    def test_fetch_recent_prs_success(self, validator):
        mock_result = Mock()
        mock_result.returncode = 0
        mock_result.stdout = json.dumps(SAMPLE_RECENT_PRS)
        fixed_now = datetime(2025, 12, 28, tzinfo=timezone.utc)

        with patch.object(validator, "run", return_value=mock_result):
            prs = validator.fetch_recent_prs(
                "2025-12-26T00:00:00Z", is_draft=False, now=fixed_now
            )

        assert prs == [7408, 7406, 7405, 7403, 7402]

    def test_fetch_recent_prs_filters_stale(self, validator):
        SAMPLE_RECENT_PRS_WITH_STALE: list[dict[str, Any]] = [
            {
                **pr,
                "labels": [
                    *pr.get("labels", []),
                    {"name": "Stale"},
                ],
            }
            for pr in SAMPLE_RECENT_PRS
        ]

        mock_result = Mock()
        mock_result.returncode = 0
        mock_result.stdout = json.dumps(SAMPLE_RECENT_PRS_WITH_STALE)
        fixed_now = datetime(2025, 12, 28, tzinfo=timezone.utc)

        with patch.object(validator, "run", return_value=mock_result):
            prs = validator.fetch_recent_prs(
                "2025-12-26T00:00:00Z", is_draft=False, now=fixed_now
            )

        assert prs == []

    def test_fetch_recent_prs_filters_old_updates(self, validator):
        fixed_now = datetime(2025, 12, 28, tzinfo=timezone.utc)
        old = fixed_now - timedelta(days=3)

        SAMPLE_RECENT_PRS_WITH_OLD_UPDATES: list[dict[str, Any]] = [
            {
                **pr,
                "updatedAt": old.isoformat(),
            }
            for pr in SAMPLE_RECENT_PRS
        ]

        mock_result = Mock()
        mock_result.returncode = 0
        mock_result.stdout = json.dumps(SAMPLE_RECENT_PRS_WITH_OLD_UPDATES)

        with patch.object(validator, "run", return_value=mock_result):
            prs = validator.fetch_recent_prs(
                "2025-12-26T00:00:00Z", is_draft=False, now=fixed_now
            )

        assert prs == []

    def test_update_pr_labels_no_changes(self, validator, mock_pr):
        with patch.object(validator, "run") as mock_run:
            validator.update_pr_labels(mock_pr, set(), set())
            mock_run.assert_not_called()

    def test_update_pr_labels_add_only(self, validator, mock_pr):
        mock_result = Mock()
        mock_result.returncode = 0

        with patch.object(validator, "run", return_value=mock_result) as mock_run:
            validator.update_pr_labels(mock_pr, {"awaiting-review"}, set())

            cmd = mock_run.call_args[0][0]
            assert "--add-label" in cmd
            assert "awaiting-review" in cmd
            assert "--remove-label" not in cmd

    def test_update_pr_labels_remove_only(self, validator, mock_pr):
        mock_result = Mock()
        mock_result.returncode = 0

        with patch.object(validator, "run", return_value=mock_result) as mock_run:
            validator.update_pr_labels(mock_pr, set(), {"blocked"})

            cmd = mock_run.call_args[0][0]
            assert "--remove-label" in cmd
            assert "blocked" in cmd
            assert "--add-label" not in cmd

    def test_update_pr_labels_add_and_remove(self, validator, mock_pr):
        mock_result = Mock()
        mock_result.returncode = 0

        with patch.object(validator, "run", return_value=mock_result) as mock_run:
            validator.update_pr_labels(mock_pr, {"awaiting-review"}, {"blocked"})

            cmd = mock_run.call_args[0][0]
            assert "--add-label" in cmd
            assert "--remove-label" in cmd

    def test_get_unresolved_review_threads_success(self, validator):
        mock_result = Mock()
        mock_result.returncode = 0
        mock_result.stdout = json.dumps(
            {
                "data": {
                    "repository": {
                        "pullRequest": {
                            "reviewThreads": {
                                "nodes": [
                                    {"isResolved": False},
                                    {"isResolved": True},
                                    {"isResolved": False},
                                ]
                            }
                        }
                    }
                }
            }
        )

        with patch.object(validator, "run", return_value=mock_result):
            count = validator.get_unresolved_review_threads(123)

        assert count == 2

    def test_process_pr_validation_invalid_pr(self, validator, mock_pr):
        validation = ValidationResult(
            is_valid=False,
            reasons=["- Missing manifest"],
            domain=None,
        )

        mock_result = Mock()
        mock_result.returncode = 0

        with patch.object(validator, "run", return_value=mock_result) as mock_run:
            validator.process_pr_validation(mock_pr, validation)

            calls = [call[0][0] for call in mock_run.call_args_list]

            comment_calls = [c for c in calls if c[1] == "pr" and c[2] == "comment"]
            assert len(comment_calls) == 1

            edit_calls = [c for c in calls if c[1] == "pr" and c[2] == "edit"]
            assert len(edit_calls) == 1
            assert "--add-label" in edit_calls[0]
            assert "pr-check-blocked" in edit_calls[0]

    def test_process_pr_validation_valid_pr(self, validator, mock_pr):
        validation = ValidationResult(
            is_valid=True,
            reasons=[],
            domain="example.com",
        )

        mock_result = Mock()
        mock_result.returncode = 0

        with patch.object(validator, "run", return_value=mock_result) as mock_run:
            validator.process_pr_validation(mock_pr, validation)

            calls = [call[0][0] for call in mock_run.call_args_list]

            comment_calls = [c for c in calls if c[1] == "pr" and c[2] == "comment"]
            assert len(comment_calls) == 2

            edit_calls = [c for c in calls if c[1] == "pr" and c[2] == "edit"]
            assert len(edit_calls) == 1

    def test_update_review_state_add_awaiting_changes(self, validator):
        pr = PR(
            number=123,
            title="Add com.example.App",
            body="Body",
            is_draft=False,
            files=["manifest.yaml"],
            comments="",
            labels={"awaiting-review"},
        )

        mock_result = Mock()
        mock_result.returncode = 0

        with patch.object(validator, "run", return_value=mock_result) as mock_run:
            validator.update_review_state(pr, thread_count=2)

            cmd = mock_run.call_args[0][0]
            assert "--add-label" in cmd
            assert "awaiting-changes" in ",".join(cmd)
            assert "--remove-label" in cmd
            assert "awaiting-review" in ",".join(cmd)

    def test_update_review_state_return_to_awaiting_review(self, validator):
        pr = PR(
            number=123,
            title="Add com.example.App",
            body="Body",
            is_draft=False,
            files=["manifest.yaml"],
            comments="",
            labels={"awaiting-changes"},
        )

        mock_result = Mock()
        mock_result.returncode = 0

        with patch.object(validator, "run", return_value=mock_result) as mock_run:
            validator.update_review_state(pr, thread_count=0)

            cmd = mock_run.call_args[0][0]
            assert "--add-label" in cmd
            assert "awaiting-review" in ",".join(cmd)
            assert "--remove-label" in cmd
            assert "awaiting-changes" in ",".join(cmd)

    def test_update_review_state_awaiting_upstream_no_change(self, validator):
        pr = PR(
            number=123,
            title="Add com.example.App",
            body="Body",
            is_draft=False,
            files=["manifest.yaml"],
            comments="",
            labels={"awaiting-changes", "awaiting-upstream"},
        )

        with patch.object(validator, "run") as mock_run:
            validator.update_review_state(pr, thread_count=0)
            mock_run.assert_not_called()


class TestIntegration:
    @pytest.fixture
    def validator(self):
        with patch.dict("os.environ", {"GITHUB_REPOSITORY": "flathub/flathub"}):
            return PRValidator()

    def test_validate_pr_full_flow(self, validator):
        pr_data = {
            "title": "Add com.example.App",
            "body": "- [x] Item\n- [x] I have read and followed all the [Submission requirements]",
            "isDraft": False,
            "files": [
                {"path": "com.example.App.yaml"},
                {"path": "flathub.json"},
            ],
            "comments": [],
            "labels": [],
            "commits": [],
        }

        review_threads_response: dict[str, Any] = {
            "data": {"repository": {"pullRequest": {"reviewThreads": {"nodes": []}}}}
        }

        mock_result_pr = Mock()
        mock_result_pr.returncode = 0
        mock_result_pr.stdout = json.dumps(pr_data)

        mock_result_threads = Mock()
        mock_result_threads.returncode = 0
        mock_result_threads.stdout = json.dumps(review_threads_response)

        mock_result_edit = Mock()
        mock_result_edit.returncode = 0

        mock_result_comment = Mock()
        mock_result_comment.returncode = 0

        def mock_run(cmd):
            if cmd[1] == "pr" and cmd[2] == "view":
                return mock_result_pr
            if cmd[1] == "api":
                return mock_result_threads
            if cmd[1] == "pr" and cmd[2] == "edit":
                return mock_result_edit
            if cmd[1] == "pr" and cmd[2] == "comment":
                return mock_result_comment
            return Mock(returncode=0)

        with patch.object(validator, "run", side_effect=mock_run):
            validator.validate_pr(123)
