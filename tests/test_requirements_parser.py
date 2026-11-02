
from src.utils.requirements_parser import parse_requirements_text


def test_exact_dependencies_are_parsed():
    """
    Exact pinned dependencies should be accepted.
    """

    content = """
requests==2.31.0
flask==3.0.0
"""

    result = parse_requirements_text(content)

    assert len(result["dependencies"]) == 2
    assert len(result["skipped"]) == 0

    assert result["dependencies"][0] == {
        "ecosystem": "PyPI",
        "name": "requests",
        "version": "2.31.0"
    }


def test_unpinned_dependencies_are_skipped():
    """
    Dependencies without an exact version should be skipped.
    """

    content = """
requests>=2.28
flask
pandas==2.2.*
"""

    result = parse_requirements_text(content)

    assert len(result["dependencies"]) == 0
    assert len(result["skipped"]) == 3


def test_duplicate_dependencies_are_removed():
    """
    Identical package/version pairs should appear only once.
    """

    content = """
requests==2.31.0
requests==2.31.0
flask==3.0.0
"""

    result = parse_requirements_text(content)

    assert len(result["dependencies"]) == 2


def test_invalid_requirement_is_skipped():

    content = """
requests==2.31.0
this is not a valid requirement !!!
"""

    result = parse_requirements_text(content)

    assert len(result["dependencies"]) == 1
    assert len(result["skipped"]) == 1

    assert (
        result["skipped"][0]["reason"]
        == "Invalid requirement format."
    )


def test_conditional_dependency_is_skipped():

    content = """
importlib-metadata==7.0.0; python_version < "3.12"
"""

    result = parse_requirements_text(content)

    assert len(result["dependencies"]) == 0
    assert len(result["skipped"]) == 1
