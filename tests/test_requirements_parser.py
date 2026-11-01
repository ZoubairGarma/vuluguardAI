
from src.utils.requirements_parser import parse_requirements_text


def test_exact_dependencies():

    content = """
requests==2.31.0
flask==3.0.0
# A comment
"""

    result = parse_requirements_text(content)

    assert len(result["dependencies"]) == 2

    assert result["dependencies"][0] == {
        "ecosystem": "PyPI",
        "name": "requests",
        "version": "2.31.0"
    }

    assert len(result["skipped"]) == 0


def test_unpinned_dependency():

    content = """
requests>=2.28
"""

    result = parse_requirements_text(content)

    assert len(result["dependencies"]) == 0
    assert len(result["skipped"]) == 1


def test_duplicate_dependencies():

    content = """
requests==2.31.0
requests==2.31.0
"""

    result = parse_requirements_text(content)

    assert len(result["dependencies"]) == 1
