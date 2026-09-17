"""Version comparison for WordPress, its plugins and its themes.

Plain tuple comparison on the string parts is not enough and neither is `packaging.version`:
WordPress components ship versions like `6.4`, `1.2.3.4`, `2.0-beta1`, `5.9.0-RC1` and, in
vulnerability feeds, the literal `*` meaning "unbounded". What matters for this tool is that

    1.9 < 1.10          (numeric, not lexical -- the classic false "up to date" result)
    6.4 == 6.4.0        (a missing component is zero, not -1)

and that a version nobody can parse never silently becomes a vulnerability match.
"""

from __future__ import annotations

import re

_NUMERIC = re.compile(r"^[vV]?(\d+(?:\.\d+)*)")

#: Sentinel used by vulnerability feeds for an open-ended range bound.
UNBOUNDED = "*"


def parse_version(value: str | None) -> tuple[int, ...] | None:
    """Return the numeric components of a version, or None when there are none.

    Any pre-release suffix is dropped rather than ordered: feeds disagree about whether `2.0-beta1`
    precedes `2.0`, and guessing would decide real findings on the strength of a label.
    """
    if value is None:
        return None
    match = _NUMERIC.match(str(value).strip())
    if not match:
        return None
    return tuple(int(part) for part in match.group(1).split("."))


def compare_versions(left: str | None, right: str | None) -> int:
    """Return -1, 0 or 1. Unparseable input on either side compares equal.

    Returning 0 for garbage is deliberate: every caller treats 0 as "nothing to report", so a
    version string this cannot read can never produce an outdated or vulnerable verdict.
    """
    left_parts = parse_version(left)
    right_parts = parse_version(right)
    if left_parts is None or right_parts is None:
        return 0

    length = max(len(left_parts), len(right_parts))
    for index in range(length):
        # A missing component is zero, so 6.4 and 6.4.0 are the same release.
        left_part = left_parts[index] if index < len(left_parts) else 0
        right_part = right_parts[index] if index < len(right_parts) else 0
        if left_part > right_part:
            return 1
        if left_part < right_part:
            return -1
    return 0


def version_in_range(
    version: str | None,
    from_version: str | None,
    from_inclusive: bool,
    to_version: str | None,
    to_inclusive: bool,
) -> bool:
    """Is `version` inside the affected range a vulnerability feed describes?

    Feeds express ranges as a lower and upper bound with separate inclusivity flags, where `*` or
    an absent bound means unbounded. The upper bound is the one that decides most matches, because
    a fixed vulnerability is published as "affects everything below the version that fixed it",
    and getting its inclusivity wrong reports every patched site as vulnerable.

    A version that cannot be parsed returns False: without a version there is nothing to match, and
    a guess here becomes a critical finding on a customer's report.
    """
    if parse_version(version) is None:
        return False

    if from_version not in (None, "", UNBOUNDED):
        comparison = compare_versions(version, from_version)
        if comparison < 0:
            return False
        if comparison == 0 and not from_inclusive:
            return False

    if to_version not in (None, "", UNBOUNDED):
        comparison = compare_versions(version, to_version)
        if comparison > 0:
            return False
        if comparison == 0 and not to_inclusive:
            return False

    return True


def is_outdated(current: str | None, latest: str | None) -> bool:
    """True when `current` is strictly older than `latest`."""
    return compare_versions(current, latest) < 0


def major_of(version: str | None) -> int | None:
    parts = parse_version(version)
    return parts[0] if parts else None
