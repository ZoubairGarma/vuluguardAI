
import pytest

from src.agents.security_test_generator import SecurityTestGenerator


@pytest.fixture
def generator():
    return SecurityTestGenerator()


def create_analysis(packages, cve_id="CVE-2023-0297"):
    return {
        "cve_id": cve_id,
        "affected_packages": packages,
    }


def create_package(
    name="pyload-ng",
    status="NOT_CHECKED",
):
    return {
        "package_name": name,
        "ecosystem": "PyPI",
        "installed_version": None,
        "version_status": status,
        "affected_ranges": ["< 0.5.0"],
        "fixed_versions": ["0.5.0"],
        "osv_ids": ["GHSA-example"],
        "purl": "pkg:pypi/pyload-ng",
    }


def test_generate_test_for_affected_package(generator):
    analysis = create_analysis([
        create_package(status="AFFECTED")
    ])

    result = generator.generate(analysis)

    assert result["total_tests"] == 1
    assert result["tests"][0]["title"] == "Confirm affected package version"
    assert result["tests"][0]["evidence"]["version_status"] == "AFFECTED"


def test_generate_test_for_not_affected_package(generator):
    analysis = create_analysis([
        create_package(status="NOT_AFFECTED")
    ])

    result = generator.generate(analysis)

    assert result["total_tests"] == 1
    assert result["tests"][0]["title"] == "Verify non-affected package version"


def test_generate_test_for_not_checked_package(generator):
    analysis = create_analysis([
        create_package(status="NOT_CHECKED")
    ])

    result = generator.generate(analysis)

    assert result["total_tests"] == 1
    assert result["tests"][0]["title"] == "Check installed package version"


def test_generate_tests_for_multiple_packages(generator):
    analysis = create_analysis([
        create_package(name="tensorflow", status="AFFECTED"),
        create_package(name="tensorflow-cpu", status="NOT_CHECKED"),
        create_package(name="tensorflow-gpu", status="NOT_AFFECTED"),
    ], cve_id="CVE-2022-21726")

    result = generator.generate(analysis)

    assert result["total_tests"] == 3
    assert len(result["tests"]) == 3
    assert result["tests"][0]["target"]["package_name"] == "tensorflow"
    assert result["tests"][1]["target"]["package_name"] == "tensorflow-cpu"
    assert result["tests"][2]["target"]["package_name"] == "tensorflow-gpu"


def test_analysis_without_cve_id_raises_error(generator):
    analysis = {
        "affected_packages": [
            create_package()
        ]
    }

    with pytest.raises(ValueError, match="cve_id"):
        generator.generate(analysis)


def test_generated_tests_require_human_approval(generator):
    analysis = create_analysis([
        create_package()
    ])

    result = generator.generate(analysis)

    assert result["approval_status"] == "PENDING_APPROVAL"
    assert result["execution_status"] == "NOT_STARTED"
    assert result["safety"]["non_destructive"] is True
    assert result["safety"]["automatic_execution"] is False
    assert result["safety"]["requires_human_approval"] is True

    for test in result["tests"]:
        assert test["approval_status"] == "PENDING_APPROVAL"
        assert test["execution_status"] == "NOT_STARTED"
        assert test["safety"] == "NON_DESTRUCTIVE"
