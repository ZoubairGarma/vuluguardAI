
from packaging.requirements import Requirement, InvalidRequirement
from packaging.utils import canonicalize_name


def parse_requirements_text(content: str) -> dict:
    """
    Parse a requirements.txt file.

    Only exact pinned versions (== or ===) are accepted
    for the first version of VulnGuard AI.

    Returns:
        {
            "dependencies": [...],
            "skipped": [...]
        }
    """

    dependencies = []
    skipped = []
    seen = set()

    lines = content.splitlines()

    for line_number, raw_line in enumerate(lines, start=1):

        line = raw_line.strip()

        # Ignore empty lines and full-line comments.
        if not line or line.startswith("#"):
            continue

        # Nested requirements and pip options are not supported yet.
        if line.startswith("-"):
            skipped.append({
                "line_number": line_number,
                "line": line,
                "reason": "Pip options and nested files are not supported yet."
            })
            continue

        # Remove a simple inline comment.
        line = line.split(" #", 1)[0].strip()

        try:
            requirement = Requirement(line)

        except InvalidRequirement:
            skipped.append({
                "line_number": line_number,
                "line": raw_line,
                "reason": "Invalid requirement format."
            })
            continue

        # Direct URL dependencies need a separate handling strategy.
        if requirement.url:
            skipped.append({
                "line_number": line_number,
                "line": raw_line,
                "reason": "Direct URL dependencies are not supported yet."
            })
            continue

        # Environment markers require environment-specific evaluation.
        if requirement.marker:
            skipped.append({
                "line_number": line_number,
                "line": raw_line,
                "reason": "Conditional dependencies are not supported yet."
            })
            continue

        specifiers = list(requirement.specifier)

        # We need one exact version.
        if (
            len(specifiers) != 1
            or specifiers[0].operator not in ("==", "===")
            or specifiers[0].version.endswith(".*")
        ):
            skipped.append({
                "line_number": line_number,
                "line": raw_line,
                "reason": "An exact pinned version (==) is required."
            })
            continue

        package_name = canonicalize_name(requirement.name)
        package_version = specifiers[0].version

        # Avoid duplicate package/version pairs.
        key = (package_name, package_version)

        if key in seen:
            continue

        seen.add(key)

        dependencies.append({
            "ecosystem": "PyPI",
            "name": package_name,
            "version": package_version
        })

    return {
        "dependencies": dependencies,
        "skipped": skipped
    }
