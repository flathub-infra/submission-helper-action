import logging

from flathub_submission_checker.constants import (
    ADD_PREFIX_RE,
    APPID_COMPONENT_RE,
    CHECKLIST_ITEMS,
    CHECKLIST_LINE_RE,
    FLATHUB_DOCS_BASE_URL,
    ROLE_CHECKLIST_RE,
    VIDEO_CHECKLIST_ITEM,
    VIDEO_LINK_RE,
    VIDEO_NA_RE,
)

logger = logging.getLogger(__name__)


def get_appid_from_pr_title(title: str) -> str | None:
    matched = ADD_PREFIX_RE.match(title)
    if not matched:
        logger.info("PR title does not match ADD_PREFIX_RE: %s", title)
        return None

    appid = title[matched.end() :].strip()
    parts = appid.split(".")

    if not (3 <= len(parts) <= 255):
        logger.info("Flatpak ID has invalid number of parts: %s", appid)
        return None

    if not all(APPID_COMPONENT_RE.match(p) for p in parts):
        logger.info("Flatpak ID has invalid component syntax: %s", appid)
        return None

    logger.info("Extracted Flatpak ID %s from PR title %s", appid, title)
    return appid


def parse_checklist(body: str) -> list[tuple[bool, str]]:
    checklist = [
        (mark.lower() == "x", text.strip())
        for mark, text in CHECKLIST_LINE_RE.findall(body)
    ]
    logger.info("Found %s checklist line(s)", len(checklist))

    unchecked = [text for checked, text in checklist if not checked]
    if unchecked:
        logger.info("Found unchecked line(s): %s", unchecked)

    return checklist


def _normalize_checklist_text(text: str) -> str:
    normalized = text.replace("*", "").replace("_", "").replace("`", "")
    return " ".join(normalized.split()).casefold()


def _role_checklist_matches(text: str) -> bool:
    return bool(ROLE_CHECKLIST_RE.search(_normalize_checklist_text(text)))


def _checklist_item_matches(text: str) -> bool:
    normalized_text = _normalize_checklist_text(text)
    return any(
        _normalize_checklist_text(item) in normalized_text for item in CHECKLIST_ITEMS
    ) or _role_checklist_matches(normalized_text)


def checklist_matches_template(checklist: list[tuple[bool, str]]) -> bool:
    texts = [_normalize_checklist_text(text) for _, text in checklist]

    missing_items = [
        item
        for item in CHECKLIST_ITEMS
        if not any(_normalize_checklist_text(item) in text for text in texts)
    ]

    if not any(_role_checklist_matches(text) for text in texts):
        missing_items.append("Role item: author/developer/contributor")

    if missing_items:
        logger.info("Found missing required item(s): %s", missing_items)
        return False
    return True


def checklist_fully_checked(checklist: list[tuple[bool, str]]) -> bool:
    if not checklist_matches_template(checklist):
        return False
    return all(checked for checked, _ in checklist)


def count_unchecked_relevant_items(checklist: list[tuple[bool, str]]) -> int:
    relevant = [checked for checked, text in checklist if _checklist_item_matches(text)]
    unchecked_count = sum(1 for checked in relevant if not checked)
    logger.info(
        "Found %s relevant checklists and %s relevant but unchecked checklists",
        len(relevant),
        unchecked_count,
    )
    return unchecked_count


def _indentation_width(line: str) -> int:
    expanded_line = line.expandtabs(4)
    return len(expanded_line) - len(expanded_line.lstrip())


def has_missing_video(body: str) -> bool:
    lines = body.splitlines()

    for i, line in enumerate(lines):
        matched = CHECKLIST_LINE_RE.match(line)
        if not matched:
            continue
        if _normalize_checklist_text(
            VIDEO_CHECKLIST_ITEM
        ) not in _normalize_checklist_text(matched.group(2)):
            continue
        if matched.group(1).lower() != "x":
            logger.info("Video checklist item is unchecked")
            return True

        video_indent = _indentation_width(line)
        continuation_lines = []
        for continuation in lines[i + 1 :]:
            if (
                CHECKLIST_LINE_RE.match(continuation)
                and _indentation_width(continuation) <= video_indent
            ):
                break
            continuation_lines.append(continuation)
        search_text = "\n".join([matched.group(2), *continuation_lines])

        for video_link in VIDEO_LINK_RE.finditer(search_text):
            if not video_link.group(0).startswith(f"{FLATHUB_DOCS_BASE_URL}/"):
                return False

        if VIDEO_NA_RE.search(search_text):
            logger.info("Video checklist item marked N/A or no video available")
            return True
        logger.info("Video checklist item has no acceptable link")
        return True

    logger.info("Video checklist item not found in PR body")
    return True
