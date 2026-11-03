\# VulnGuard AI — Person A Technical Documentation



\## 1. Project Overview



\### 1.1 Project Description



VulnGuard AI is an AI-assisted vulnerability identification and risk prioritization system for software dependencies.



The system collects vulnerability information from multiple security data sources, enriches vulnerability records with relevant security indicators, evaluates their risk level, and helps security analysts prioritize vulnerabilities.



It also integrates a Large Language Model (LLM) to generate explanations and recommendations, and provides a controlled security testing workflow based on human approval.



\### 1.2 Main Objectives



The main objectives of VulnGuard AI are:



\- Collect vulnerability information from reliable security databases.

\- Enrich vulnerability records with severity and exploitation-related indicators.

\- Extract and prepare relevant features for analysis.

\- Assess and prioritize vulnerabilities using a custom risk scoring approach.

\- Provide contextual vulnerability analysis.

\- Generate understandable vulnerability explanations using an LLM.

\- Generate security test plans based on vulnerability analysis.

\- Require explicit human approval before executing security tests.

\- Execute only approved, controlled, and non-destructive checks.



\### 1.3 Person A Responsibilities



Person A is responsible for the vulnerability intelligence and security analysis components of the system.



The implemented components include:



1\. \*\*Data Ingestion:\*\* collecting vulnerability information from OSV, EPSS, and CISA KEV.

2\. \*\*Data Preprocessing:\*\* inspecting, integrating, validating, and preparing vulnerability datasets.

3\. \*\*Feature Engineering:\*\* extracting relevant features from vulnerability records.

4\. \*\*Machine Learning Exploration:\*\* evaluating baseline models and investigating the relationship between vulnerability features and KEV labels.

5\. \*\*Risk Scoring:\*\* calculating a custom vulnerability prioritization score.

6\. \*\*Vulnerability Analysis:\*\* retrieving and analyzing vulnerability context and affected package information.

7\. \*\*LLM Integration:\*\* generating explanations using a locally hosted Ollama model.

8\. \*\*Security Test Generation:\*\* generating package-version verification

## 2. Data Ingestion

### 2.1 Overview

The data ingestion component collects vulnerability-related information from three security data sources:

- **OSV (Open Source Vulnerabilities):** provides vulnerability records associated with open-source packages and ecosystems.
- **EPSS (Exploit Prediction Scoring System):** provides daily estimates of the probability that a published CVE will be exploited in the wild within the next 30 days.
- **CISA KEV (Known Exploited Vulnerabilities):** provides a catalog of vulnerabilities known to have been exploited in real-world attacks.

These sources provide complementary information used in subsequent preprocessing, feature engineering, and risk assessment stages.

### 2.2 OSV Data Ingestion

**Implementation file:** `src/ingestion/osv_ingestion.py`

The OSV ingestion module collects vulnerability records from the Open Source Vulnerabilities database.

The collected records provide information such as:

- Vulnerability identifiers.
- CVE aliases.
- Vulnerability descriptions.
- Affected package information.
- Ecosystem information.
- Introduced and fixed versions.
- Vulnerability references and metadata when available.

The downloaded OSV archive was extracted into:

`data/raw/osv/`

**Collected dataset:**

- Total vulnerability records: 26,773 JSON records.
- CVE aliases identified: 13,992.
- Unique CVEs identified during dataset analysis: 6,773.

OSV data is particularly important for identifying affected packages and determining whether a specific package version falls within a reported affected range.

### 2.3 EPSS Data Ingestion

**Implementation file:** `src/ingestion/epss_ingestion.py`

The EPSS ingestion module collects the Exploit Prediction Scoring System dataset.

EPSS provides two important fields:

- **EPSS Score:** an estimate of the probability of exploitation activity within the next 30 days.
- **Percentile:** the relative position of a vulnerability's EPSS score compared with other CVEs.

The collected dataset was stored under:

`data/raw/epss/`

**Collected dataset:**

- Total records: 398,784.
- Number of columns: 3.
- Missing values: none in the downloaded dataset.

During dataset integration, EPSS information was matched with the CVE identifiers extracted from OSV records.

A total of 6,709 CVEs were successfully matched with EPSS data, while 64 CVEs had no matching EPSS record.

### 2.4 CISA KEV Data Ingestion

**Implementation file:** `src/ingestion/kev_ingestion.py`

The KEV ingestion module collects vulnerability information from the CISA Known Exploited Vulnerabilities catalog.

The catalog identifies vulnerabilities for which exploitation has been observed and confirmed by CISA.

The KEV dataset is used as an additional exploitation-related prioritization signal.

**Collected dataset:**

- Snapshot date: October 30, 2026.
- Total vulnerabilities: 1,766.

During integration, 21 CVEs from the analyzed OSV dataset were matched with the KEV catalog.

A KEV match indicates that the vulnerability is listed in the catalog. The absence of a match does not prove that a vulnerability has never been exploited.

### 2.5 Data Storage Structure

The ingestion modules organize the downloaded datasets under the raw data directory:

```text
data/
└── raw/
    ├── osv/
    ├── epss/
    └── kev/
```

The raw datasets are retained as source inputs for subsequent preprocessing and analysis.

### 2.6 Role of Each Data Source

| Data source | Main contribution |
|---|---|
| OSV | Vulnerability descriptions and affected package/version information |
| EPSS | Exploitation probability estimates and percentiles |
| CISA KEV | Evidence that a vulnerability is listed as known exploited |

Combining these sources provides a richer vulnerability context than relying on a single dataset.

## 3. Data Preprocessing and Feature Engineering

### 3.1 Overview

After collecting vulnerability information from OSV, EPSS, and CISA KEV, a preprocessing pipeline was developed to inspect, integrate, validate, and transform the raw datasets.

The main objective was to create a unified vulnerability dataset containing package information, severity indicators, exploitation-related features, and vulnerability metadata.

The preprocessing workflow includes:

1. Dataset inspection.
2. Coverage analysis.
3. Dataset integration.
4. Data validation.
5. CVSS severity inspection and extraction.
6. Feature engineering.
7. CVSS score calculation.
8. Data quality auditing.
9. ML dataset preparation.

### 3.2 Dataset Inspection and Coverage Analysis

**Implementation files:**

- `src/preprocessing/inspect_datasets.py`
- `src/preprocessing/analyze_coverage.py`

These scripts were developed to examine the structure and completeness of the collected datasets.

The inspection stage identifies available fields, record counts, missing information, and the distribution of vulnerability identifiers.

The coverage analysis evaluates how much OSV vulnerability information can be enriched using EPSS and KEV data.

The integration results showed:

| Metric | Result |
|---|---:|
| OSV vulnerability records | 26,773 |
| Unique CVEs | 6,773 |
| CVEs matched with EPSS | 6,709 |
| CVEs without EPSS match | 64 |
| CVEs matched with KEV | 21 |

### 3.3 Dataset Integration

**Implementation file:** `src/preprocessing/integrate_datasets.py`

The integration module combines vulnerability information from the different sources using CVE identifiers as the main matching reference.

The resulting dataset brings together:

- OSV vulnerability metadata.
- CVE identifiers and aliases.
- Affected package information.
- EPSS scores and percentiles when available.
- KEV membership information.

The integration process makes it possible to analyze vulnerability severity and exploitation-related signals together.

### 3.4 Data Validation

**Implementation file:** `src/preprocessing/validate_datasets.py`

A validation stage was implemented to check the consistency of the integrated datasets.

This step helps identify missing values, inconsistencies, and potential problems before feature engineering and risk assessment.

### 3.5 CVSS Severity Inspection

**Implementation file:** `src/preprocessing/inspect_severity.py`

This script examines the availability and structure of CVSS severity information in the vulnerability records.

CVSS information is important because it provides a standardized way to describe the technical severity of vulnerabilities.

The inspection stage prepares the data for CVSS score extraction and calculation.

### 3.6 Feature Engineering

**Implementation file:** `src/preprocessing/feature_engineering.py`

Feature engineering transforms the collected vulnerability information into structured variables suitable for analysis.

The engineered features include vulnerability information, severity indicators, exploitation-related signals, and package-related metadata.

The resulting feature dataset is stored as:

`data/processed/ml_features.csv`

**Dataset dimensions:**

- Number of rows: 6,773.
- Number of columns: 81.

Each row represents a unique CVE in the prepared dataset.

### 3.7 CVSS Score Calculation

**Implementation files:**

- `src/preprocessing/test_cvss_calculator.py`
- `src/preprocessing/calculate_cvss_scores.py`

The CVSS processing component extracts and calculates vulnerability severity scores from available CVSS vectors.

The implementation supports CVSS v3 and CVSS v4 information.

The processing results included:

- 14,533 CVSS entries parsed.
- 6,505 unique CVEs represented in the extracted CVSS information.

The calculated scores are used later by the risk scoring component.

### 3.8 Data Quality Audit

**Implementation file:** `src/preprocessing/data_quality_audit.py`

The data quality audit evaluates the prepared data before its use in machine learning experiments.

This stage helps identify data completeness issues and verifies the structure of the generated features.

### 3.9 ML Dataset Preparation

**Implementation file:** `src/preprocessing/prepare_ml_dataset.py`

The final preprocessing stage prepares the structured dataset for machine learning exploration.

The resulting dataset contains:

- 6,773 CVE records.
- 79 input features.
- KEV membership as the target label.

Only 21 records were labeled as positive KEV examples, making the dataset highly imbalanced.

This imbalance is an important limitation considered during model evaluation.

### 3.10 Generated Data Structure

The main processed outputs include:

```text
data/
└── processed/
    ├── ml_features.csv
    ├── cve_features.csv
    ├── cvss_scores.csv
    └── ...
```

The preprocessing pipeline transforms raw vulnerability information into structured datasets that can be reused by the risk scoring and machine learning components.


## 3. Data Preprocessing and Feature Engineering

### 3.1 Overview

After collecting vulnerability information from OSV, EPSS, and CISA KEV, a preprocessing pipeline was developed to inspect, integrate, validate, and transform the raw datasets.

The main objective was to create a unified vulnerability dataset containing package information, severity indicators, exploitation-related features, and vulnerability metadata.

The preprocessing workflow includes:

1. Dataset inspection.
2. Coverage analysis.
3. Dataset integration.
4. Data validation.
5. CVSS severity inspection and extraction.
6. Feature engineering.
7. CVSS score calculation.
8. Data quality auditing.
9. ML dataset preparation.

### 3.2 Dataset Inspection and Coverage Analysis

**Implementation files:**

- `src/preprocessing/inspect_datasets.py`
- `src/preprocessing/analyze_coverage.py`

These scripts were developed to examine the structure and completeness of the collected datasets.

The inspection stage identifies available fields, record counts, missing information, and the distribution of vulnerability identifiers.

The coverage analysis evaluates how much OSV vulnerability information can be enriched using EPSS and KEV data.

The integration results showed:

| Metric | Result |
|---|---:|
| OSV vulnerability records | 26,773 |
| Unique CVEs | 6,773 |
| CVEs matched with EPSS | 6,709 |
| CVEs without EPSS match | 64 |
| CVEs matched with KEV | 21 |

### 3.3 Dataset Integration

**Implementation file:** `src/preprocessing/integrate_datasets.py`

The integration module combines vulnerability information from the different sources using CVE identifiers as the main matching reference.

The resulting dataset brings together:

- OSV vulnerability metadata.
- CVE identifiers and aliases.
- Affected package information.
- EPSS scores and percentiles when available.
- KEV membership information.

The integration process makes it possible to analyze vulnerability severity and exploitation-related signals together.

### 3.4 Data Validation

**Implementation file:** `src/preprocessing/validate_datasets.py`

A validation stage was implemented to check the consistency of the integrated datasets.

This step helps identify missing values, inconsistencies, and potential problems before feature engineering and risk assessment.

### 3.5 CVSS Severity Inspection

**Implementation file:** `src/preprocessing/inspect_severity.py`

This script examines the availability and structure of CVSS severity information in the vulnerability records.

CVSS information is important because it provides a standardized way to describe the technical severity of vulnerabilities.

The inspection stage prepares the data for CVSS score extraction and calculation.

### 3.6 Feature Engineering

**Implementation file:** `src/preprocessing/feature_engineering.py`

Feature engineering transforms the collected vulnerability information into structured variables suitable for analysis.

The engineered features include vulnerability information, severity indicators, exploitation-related signals, and package-related metadata.

The resulting feature dataset is stored as:

`data/processed/ml_features.csv`

**Dataset dimensions:**

- Number of rows: 6,773.
- Number of columns: 81.

Each row represents a unique CVE in the prepared dataset.

### 3.7 CVSS Score Calculation

**Implementation files:**

- `src/preprocessing/test_cvss_calculator.py`
- `src/preprocessing/calculate_cvss_scores.py`

The CVSS processing component extracts and calculates vulnerability severity scores from available CVSS vectors.

The implementation supports CVSS v3 and CVSS v4 information.

The processing results included:

- 14,533 CVSS entries parsed.
- 6,505 unique CVEs represented in the extracted CVSS information.

The calculated scores are used later by the risk scoring component.

### 3.8 Data Quality Audit

**Implementation file:** `src/preprocessing/data_quality_audit.py`

The data quality audit evaluates the prepared data before its use in machine learning experiments.

This stage helps identify data completeness issues and verifies the structure of the generated features.

### 3.9 ML Dataset Preparation

**Implementation file:** `src/preprocessing/prepare_ml_dataset.py`

The final preprocessing stage prepares the structured dataset for machine learning exploration.

The resulting dataset contains:

- 6,773 CVE records.
- 79 input features.
- KEV membership as the target label.

Only 21 records were labeled as positive KEV examples, making the dataset highly imbalanced.

This imbalance is an important limitation considered during model evaluation.

### 3.10 Generated Data Structure

The main processed outputs include:

```text
data/
└── processed/
    ├── ml_features.csv
    ├── cve_features.csv
    ├── cvss_scores.csv
    └── ...
```

The preprocessing pipeline transforms raw vulnerability information into structured datasets that can be reused by the risk scoring and machine learning components.


## 5. Risk Scoring and Vulnerability Prioritization

### 5.1 Objective

The risk scoring component assigns a prioritization score to each vulnerability to help identify which vulnerabilities should be reviewed first.

The implementation combines:

- CVSS severity information.
- EPSS exploitation probability estimates.
- CISA KEV catalog membership.

The resulting score is a custom prioritization index and is not a probability of exploitation.

### 5.2 Implementation

**Implementation file:** `src/agents/risk_scoring.py`

**Input files:**

- `data/processed/cve_features.csv`
- `data/processed/cvss_scores.csv`

**Output file:**

- `data/processed/risk/risk_assessment.csv`

The component processes the available vulnerability information and produces a risk assessment for each CVE.

### 5.3 Scoring Methodology

For vulnerabilities that are not listed in KEV, the scoring system combines normalized CVSS and EPSS values using the following weights:

- CVSS contribution: 60%.
- EPSS contribution: 40%.

When only one of these indicators is available, the available indicator is used after renormalizing the weights.

The implementation follows these rules:

1. CVSS v3 is preferred when available.
2. CVSS v4 is used as a fallback.
3. KEV-listed vulnerabilities receive a priority score of 100.
4. When neither CVSS nor EPSS is available, the score remains unknown.

The KEV override ensures that vulnerabilities listed in the known exploited catalog receive the highest prioritization.

### 5.4 Risk Classification

The calculated score is mapped to one of five risk levels.

| Risk level | Score range |
|---|---:|
| LOW | Below 30 |
| MEDIUM | 30 to below 60 |
| HIGH | 60 to below 80 |
| CRITICAL | 80 to 100 |
| UNKNOWN | No usable score |

### 5.5 Assessment Results

The risk scoring component processed 6,773 vulnerabilities.

The resulting distribution was:

| Risk level | Number of vulnerabilities |
|---|---:|
| CRITICAL | 79 |
| HIGH | 235 |
| MEDIUM | 5,442 |
| LOW | 1,013 |
| UNKNOWN | 4 |
| **Total** | **6,773** |

The scoring basis was distributed as follows:

| Scoring basis | Number of vulnerabilities |
|---|---:|
| CVSS and EPSS | 6,424 |
| EPSS only | 264 |
| CVSS only | 60 |
| KEV override | 21 |
| No available data | 4 |

### 5.6 Interpretation

The risk score provides a consistent way to prioritize vulnerabilities using available severity and exploitation-related information.

KEV membership acts as an additional priority signal because it indicates that a vulnerability is included in CISA's catalog of known exploited vulnerabilities.

The score should be interpreted as a prioritization mechanism rather than a statistically calibrated probability.

### 5.7 Conclusion

The risk scoring component transforms vulnerability intelligence into actionable priority levels.

Its output can be used by subsequent components, including vulnerability analysis and security test generation, to support a more structured vulnerability management workflow.

## 6. Vulnerability Context and Analysis

### 6.1 Objective

The vulnerability context and analysis component provides detailed information about a vulnerability and its affected packages.

Its purpose is to transform raw vulnerability records into structured analysis that can be used by the LLM explanation component and the security test generation workflow.

### 6.2 Vulnerability Context Module

**Implementation file:** `src/agents/vulnerability_context.py`

The vulnerability context module is responsible for preparing the information required for vulnerability analysis.

It provides contextual information used by the analyzer, including vulnerability metadata and affected package information.

The module was validated using dedicated unit tests.

### 6.3 Vulnerability Analyzer

**Implementation file:** `src/agents/vulnerability_analyzer.py`

The `VulnerabilityAnalyzer` class provides two main methods:

- `analyze_context(context, installed_packages=None)`
- `analyze(cve_id, installed_packages=None)`

A convenience function named `analyze_vulnerability` is also available.

The analyzer produces structured information including:

- Vulnerability identifier.
- Risk information.
- Description.
- Available advisories.
- Affected packages.
- Version ranges.
- Fixed versions.
- Package version status.
- Analysis and recommendations.
- Metadata.

### 6.4 Package Version Status

The analyzer uses four statuses to describe the relationship between an installed package version and the vulnerability information.

| Status | Meaning |
|---|---|
| AFFECTED | The installed version falls within a reported affected range. |
| NOT_AFFECTED | The installed version is outside the reported affected range. |
| UNKNOWN | Available information is insufficient to determine the status. |
| NOT_CHECKED | No installed package version was provided for verification. |

These statuses help distinguish confirmed version-range results from cases where additional information is required.

### 6.5 Affected Version Range Evaluation

The function `version_in_affected_range(installed_version, affected_ranges)` evaluates whether a package version falls within an OSV affected range.

It supports OSV range events such as:

- `introduced`
- `fixed`
- `last_affected`
- `limit`

The implementation recognizes ECOSYSTEM and SEMVER range types.

GIT ranges are not evaluated by this version comparison function.

The function returns:

- `True` when the version is within a supported affected range.
- `False` when it is outside the supported affected range.
- `None` when the available information cannot support a reliable determination.

### 6.6 Multiple Packages and Version Ranges

A vulnerability may affect multiple packages or multiple version ranges.

The analyzer preserves the affected ranges separately for each package.

This is important because combining version boundaries from different packages or branches could produce incorrect conclusions.

The analysis therefore retains package-specific evidence, including affected ranges and fixed versions.

### 6.7 Interpretation and Limitations

The analyzer relies on the vulnerability information available in the source records.

A missing KEV match does not prove that a vulnerability has never been exploited.

Similarly, an UNKNOWN version status does not mean that a package is safe or vulnerable. It means that the available evidence is insufficient for a reliable determination.

The analyzer does not infer version intervals from flattened fixed-version information.

### 6.8 Validation

The vulnerability context module was validated with 8 passing tests.

The original vulnerability analyzer implementation was validated with 10 passing tests.

These tests support the correctness of the implemented analysis behavior and version-range handling.

### 6.9 Conclusion

The vulnerability context and analyzer components provide structured vulnerability intelligence for the subsequent stages of the system.

Their outputs serve as inputs to LLM-based explanations and security test generation.

## 7. LLM Integration

### 7.1 Objective

The LLM integration component aims to transform structured vulnerability information into understandable explanations and recommendations.

Instead of presenting only technical vulnerability data, the system uses a Large Language Model (LLM) to generate human-readable descriptions that can help security analysts understand vulnerability findings.

### 7.2 Local LLM Environment

The project uses Ollama to run a language model locally.

**Selected model:** `llama3.2:3b`

**Local API endpoint:**

`http://localhost:11434/api/generate`

Using a locally hosted model allows the application to communicate with the LLM through an HTTP API without depending on a remotely hosted inference service.

### 7.3 Provider Architecture

The LLM integration uses a provider-based architecture to separate the general LLM interface from the specific Ollama implementation.

**Implementation files:**

- `src/agents/llm/base.py`
- `src/agents/llm/ollama_provider.py`

The base module defines the common interface for LLM providers.

The Ollama provider implements the communication with the locally hosted model.

This separation makes the LLM integration easier to maintain and allows other providers to be integrated in the future.

### 7.4 Vulnerability Explanation Component

**Implementation file:** `src/agents/llm_explanation.py`

The LLM explanation component uses structured vulnerability information to generate explanations.

Its purpose is to make technical findings easier to understand by presenting relevant vulnerability context in natural language.

The generated explanations can include:

- Vulnerability summaries.
- Technical impact descriptions.
- Risk-related explanations.
- Remediation recommendations.

The LLM is used as an explanation assistant and does not replace the structured vulnerability analysis or risk scoring components.

### 7.5 Integration Testing

The following scripts were created to validate the integration:

- `src/agents/run_llm_integration.py`
- `src/agents/test_multiple_explanations.py`

Unit tests were also developed for the provider and explanation components.

Test results:

| Component | Tests passed |
|---|---:|
| LLM provider | 4 |
| LLM explanation | 6 |
| **Total** | **10** |

### 7.6 Reliability Considerations

LLM-generated explanations may contain inaccurate or unsupported statements.

For this reason:

- Structured vulnerability data remains the primary source of technical facts.
- Risk scores are calculated by the dedicated risk scoring component.
- The LLM must not be treated as an authoritative vulnerability database.
- Generated explanations should be reviewed before being used in security decisions.

The current implementation was functionally tested, but further work is needed to improve factual consistency and output validation.

### 7.7 Conclusion

The LLM integration adds a natural-language explanation layer to VulnGuard AI.

By combining structured vulnerability analysis with locally generated explanations, the system aims to make vulnerability findings easier to interpret while keeping technical decisions grounded in structured data.

## 8. Security Test Generation

### 8.1 Objective

The Security Test Generator transforms vulnerability analysis results into structured security test plans.

Its purpose is to prepare package-version verification tests based on the affected package information provided by the Vulnerability Analyzer.

The generator creates test plans but does not execute them.

### 8.2 Implementation

**Implementation file:** `src/agents/security_test_generator.py`

The `SecurityTestGenerator` class provides the following method:

- `generate(analysis)`

The method receives a structured vulnerability analysis and generates a test plan.

It validates the input information, including the CVE identifier and affected package data.

### 8.3 Generated Test Structure

The generator creates one package-version verification test for each affected package entry.

Each generated test contains:

- Test identifier.
- CVE identifier.
- Test type.
- Test title.
- Test objective.
- Target package.
- Evidence from the vulnerability analysis.
- Verification steps.
- Expected result.
- Safety classification.
- Approval status.
- Execution status.

The evidence includes available affected ranges, fixed versions, OSV identifiers, and package URLs (PURLs).

### 8.4 Package Version Status Mapping

The generator uses the package version status from the vulnerability analysis to determine the purpose of each test.

| Version status | Generated test title |
|---|---|
| AFFECTED | Confirm affected package version |
| NOT_AFFECTED | Verify non-affected package version |
| NOT_CHECKED | Check installed package version |
| UNKNOWN | Review package version manually |

This mapping allows the generated test plan to reflect the available vulnerability evidence.

### 8.5 Safety Mechanisms

The generator follows a Human-in-the-Loop approach.

Every generated test plan initially receives:

- Approval status: `PENDING_APPROVAL`.
- Execution status: `NOT_EXECUTED`.
- Safety classification: `NON_DESTRUCTIVE`.

The generated plan also specifies:

- `non_destructive = True`
- `automatic_execution = False`
- `requires_human_approval = True`

These settings ensure that test generation and test execution remain separate operations.

### 8.6 Unit Testing

**Test file:** `tests/agents/test_security_test_generator.py`

Six unit tests were implemented to validate:

- AFFECTED package handling.
- NOT_AFFECTED package handling.
- NOT_CHECKED package handling.
- Multiple package generation.
- Missing CVE identifier validation.
- Human approval requirements and prevention of automatic execution.

**Result:** 6 tests passed.

### 8.7 Analyzer and Generator Integration

**Integration file:** `src/agents/test_security_generation_integration.py`

An integration script connects the Vulnerability Analyzer to the Security Test Generator.

The workflow was tested using:

`CVE-2023-0297`

The execution produced:

- Risk level: CRITICAL.
- One affected package entry.
- Generated test ID: `CVE-2023-0297-TEST-001`.
- Target package: `pyload-ng`.
- Version status: `NOT_CHECKED`.
- Approval status: `PENDING_APPROVAL`.
- Execution status: `NOT_EXECUTED`.

The NOT_CHECKED status indicates that the installed package version had not yet been verified.

### 8.8 Conclusion

The Security Test Generator converts vulnerability analysis into structured, traceable, and non-destructive test plans.

By separating test generation from execution, the component provides a safe foundation for the Human-in-the-Loop approval workflow.

## 9. Human-in-the-Loop (HITL)

### 9.1 Objective

The Human-in-the-Loop (HITL) component introduces a manual approval mechanism between security test generation and execution.

Its main objective is to ensure that a security reviewer explicitly approves or rejects each generated test plan before any test is executed.

This mechanism prevents automatic execution and provides human oversight over the testing workflow.

### 9.2 Implementation

**Implementation file:** `src/agents/human_approval.py`

The `HumanApprovalManager` class provides two main methods:

- `approve(test_plan, reviewer)`
- `reject(test_plan, reviewer, reason)`

The approval manager validates the test plan before processing a decision.

It checks that:

- The input is a valid test plan.
- A reviewer has been provided.
- The test list exists.
- Automatic execution is disabled.
- Human approval is required.
- The test plan has not already been executed.
- The current approval status is `PENDING_APPROVAL`.

### 9.3 Approval Workflow

When a reviewer approves a test plan:

1. The manager validates the plan.
2. A deep copy of the original plan is created.
3. The approval status is updated to `APPROVED`.
4. The reviewer identity is recorded.
5. The approval timestamp is recorded.
6. The approval decision is stored.
7. The execution status remains `NOT_EXECUTED`.

Approval authorizes the test plan to proceed to the controlled executor, but does not execute any test.

### 9.4 Rejection Workflow

When a reviewer rejects a test plan:

1. The manager validates the plan.
2. A non-empty rejection reason is required.
3. A deep copy of the original plan is created.
4. The approval status is updated to `REJECTED`.
5. The reviewer identity is recorded.
6. The rejection timestamp and reason are stored.
7. The execution status remains `NOT_EXECUTED`.

Rejected plans cannot proceed through the normal approved execution workflow.

### 9.5 Data Integrity and Safety

The approval manager uses deep copying to preserve the original test plan.

This ensures that approval or rejection decisions do not directly modify the original generated plan.

The manager also prevents:

- Approving a plan that has already been approved or rejected.
- Processing a plan that has already been executed.
- Approving a plan with unsafe execution configuration.
- Rejecting a plan without a reason.

### 9.6 Unit Testing

**Test file:** `tests/agents/test_human_approval.py`

Seven unit tests were implemented to validate:

- Successful approval.
- Successful rejection.
- Prevention of repeated approval.
- Mandatory rejection reason.
- Reviewer information recording.
- Preservation of the original plan.
- Enforcement of safety configuration.

**Result:** 7 tests passed.

### 9.7 Interactive Integration Testing

**Integration file:** `src/agents/test_hitl_integration.py`

An interactive integration script connects the following components:

1. Vulnerability Analyzer.
2. Security Test Generator.
3. HumanApprovalManager.

The reviewer is asked to approve or reject the generated test plan.

Two scenarios were successfully demonstrated:

**Scenario 1 — Approval**

- Reviewer decision: YES.
- Approval status: `APPROVED`.
- Execution status: `NOT_EXECUTED`.

**Scenario 2 — Rejection**

- Reviewer decision: NO.
- Approval status: `REJECTED`.
- Rejection reason: `no reason`.
- Execution status: `NOT_EXECUTED`.

Both scenarios confirmed that the HITL component records the review decision without executing the test plan.

### 9.8 Conclusion

The Human-in-the-Loop component provides an essential safety and governance layer.

It ensures that test execution is a separate, explicitly authorized operation and that reviewer decisions are recorded for traceability.

## 10. Controlled Security Test Execution

### 10.1 Objective

The Controlled Security Test Executor is responsible for executing approved security test plans.

Its main objective is to verify whether an installed software package version falls within a vulnerability's reported affected version ranges.

The executor follows strict safety rules and only performs approved, non-destructive package-version checks.

### 10.2 Implementation

**Implementation file:** `src/agents/security_test_executor.py`

The `SecurityTestExecutor` class is responsible for validating and executing security test plans.

It supports the following test type:

`PACKAGE_VERSION_CHECK`

The executor uses Python's `importlib.metadata` module to retrieve installed package versions from the local Python environment.

### 10.3 Execution Preconditions

Before executing a test plan, the executor verifies that:

- The plan approval status is `APPROVED`.
- Automatic execution is disabled.
- Human approval is required.
- The plan is configured as non-destructive.
- The plan execution status is `NOT_EXECUTED`.
- Each individual test is approved.
- Each test has not already been executed.
- Each test uses the supported test type.
- Each test has the expected safety classification.

If these conditions are not satisfied, execution is prevented.

### 10.4 Package Version Verification

The executor retrieves the installed version of the target package using:

`importlib.metadata.version(package_name)`

It then compares the installed version with the affected version ranges provided by the generated test plan.

The comparison uses the `version_in_affected_range()` function from the vulnerability analyzer.

Possible outcomes include:

| Result | Meaning |
|---|---|
| AFFECTED | The installed version is within a supported affected range. |
| NOT_AFFECTED | The installed version is outside the supported affected range. |
| UNKNOWN | The available range information is insufficient for a reliable determination. |
| NOT_INSTALLED | The target package is not installed in the local environment. |
| SKIPPED | The test cannot be performed because required information or support is missing. |

### 10.5 Non-Destructive Execution

The executor performs read-only package metadata checks.

It does not:

- Install or uninstall packages.
- Modify package versions.
- Execute vulnerability exploits.
- Modify project files.
- Perform destructive security operations.

The executor is designed to verify package-version information without changing the local environment.

### 10.6 Execution Results and Data Integrity

The executor creates a deep copy of the approved test plan before processing it.

This preserves the original plan and prevents execution results from modifying the original generated test plan.

The execution result is recorded in the copied plan.

Depending on the outcome of the individual tests, the overall execution status can be:

- `COMPLETED`
- `SKIPPED`
- `PARTIAL`

### 10.7 Unit Testing

**Test file:** `tests/agents/test_security_test_executor.py`

Twelve unit tests were implemented to validate the executor.

The tests cover:

- Execution permission validation.
- Prevention of unauthorized execution.
- Preservation of the original test plan.
- Successful package-version verification.
- Detection of an affected package version.
- Detection of a non-affected package version.
- Handling of unsupported GIT version ranges.
- Handling of packages that are not installed.

**Result: 12 tests passed.**

### 10.8 End-to-End Execution Integration

**Integration file:** `src/agents/test_execution_integration.py`

The integration script connects four components:

1. Vulnerability Analyzer.
2. Security Test Generator.
3. HumanApprovalManager.
4. SecurityTestExecutor.

The workflow was tested using:

`CVE-2023-0297`

The approved scenario produced the following results:

- Test plan approval status: `APPROVED`.
- Reviewer: `Noussaaa`.
- Target package: `pyload-ng`.
- Package verification result: `NOT_INSTALLED`.
- Execution status: `COMPLETED`.

The original test plan retained its execution status:

`NOT_EXECUTED`

A rejection scenario was also successfully tested. In that scenario, the test plan received the `REJECTED` status and remained `NOT_EXECUTED`.

### 10.9 Conclusion

The controlled executor completes the security testing workflow by executing approved package-version checks.

Combined with the Human-in-the-Loop approval manager, it provides a controlled process that separates vulnerability analysis, test generation, human authorization, and execution.

## 11. End-to-End Integration

### 11.1 Objective

The end-to-end integration connects the vulnerability analysis, security test generation, human approval, and controlled execution components into a complete workflow.

The objective is to demonstrate how the different Person A modules work together to process a vulnerability and perform an approved package-version verification.

### 11.2 Integration Architecture

The complete workflow consists of four main components:

1. **Vulnerability Analyzer:** retrieves and analyzes vulnerability information.
2. **Security Test Generator:** generates a structured security test plan.
3. **HumanApprovalManager:** processes the reviewer's approval or rejection decision.
4. **SecurityTestExecutor:** executes approved package-version verification tests.

### 11.3 Complete Workflow

The integration follows these steps:

1. A CVE identifier is provided as input.
2. The Vulnerability Analyzer retrieves and analyzes the vulnerability context.
3. The Security Test Generator creates a test plan.
4. The test plan receives the initial status `PENDING_APPROVAL`.
5. A human reviewer approves or rejects the plan.
6. If approved, the plan can be passed to the controlled executor.
7. If rejected, the workflow stops without executing the tests.
8. The executor performs the permitted package-version checks.
9. The execution results are returned in the processed test plan.

### 11.4 Integration Implementation

**Implementation file:** `src/agents/test_execution_integration.py`

This script demonstrates the complete workflow using the following components:

- `VulnerabilityAnalyzer`
- `SecurityTestGenerator`
- `HumanApprovalManager`
- `SecurityTestExecutor`

The integration was tested using:

`CVE-2023-0297`

### 11.5 Successful Approval Scenario

In the approved scenario, the reviewer authorized the generated test plan.

The observed results were:

| Property | Result |
|---|---|
| CVE | CVE-2023-0297 |
| Reviewer | Noussaaa |
| Approval status | APPROVED |
| Target package | pyload-ng |
| Package verification | NOT_INSTALLED |
| Execution status | COMPLETED |
| Original plan execution status | NOT_EXECUTED |

The package was not installed in the local Python environment. Therefore, the executor correctly reported `NOT_INSTALLED`.

The execution workflow completed without modifying the original test plan.

### 11.6 Rejection Scenario

A second integration scenario was executed to validate the rejection workflow.

The reviewer rejected the generated test plan and provided a rejection reason.

The observed results were:

- Approval status: `REJECTED`.
- Execution status: `NOT_EXECUTED`.

This confirmed that rejected plans do not proceed through the approved execution workflow.

### 11.7 Conclusion

The end-to-end integration demonstrates how vulnerability analysis can be connected to controlled security testing.

It establishes a complete workflow with explicit human authorization, execution controls, and preservation of the original test plan.

---

## 12. Testing and Validation

### 12.1 Objective

Testing was performed to validate the behavior of the Person A components and verify that the main security workflow operates as expected.

The validation strategy includes unit tests and integration scripts.

### 12.2 Unit Testing

The following test modules were implemented:

| Test file | Tests passed |
|---|---:|
| `tests/agents/test_vulnerability_context.py` | 8 |
| Vulnerability analyzer tests | 10 |
| LLM provider tests | 4 |
| LLM explanation tests | 6 |
| `tests/agents/test_security_test_generator.py` | 6 |
| `tests/agents/test_human_approval.py` | 7 |
| `tests/agents/test_security_test_executor.py` | 12 |

The tests cover vulnerability context processing, vulnerability analysis, LLM integration, test generation, human approval, and controlled execution.

### 12.3 Integration Testing

The following integration scripts were used:

- `src/agents/test_security_generation_integration.py`
- `src/agents/test_hitl_integration.py`
- `src/agents/test_execution_integration.py`

These scripts validate the interaction between the main Person A components.

Both approval and rejection scenarios were demonstrated during integration testing.

### 12.4 Overall Test Results

The following command was executed:

```powershell
python -m pytest tests/agents/ -v
```

**Reported result: 78 tests passed.**

This result applies to the test suite under `tests/agents/` at the time of execution. It should not be interpreted as confirmation that every test in the entire repository has passed.

### 12.5 Validation Summary

The validation activities demonstrated that:

- Vulnerability context and analysis modules can process vulnerability information.
- LLM provider and explanation components can be tested independently.
- Security test plans are generated with pending approval.
- Human reviewers can approve or reject test plans.
- Unauthorized execution is prevented.
- Approved package-version checks can be performed.
- Rejected plans remain unexecuted.
- Original test plans are preserved during approval and execution processing.

### 12.6 Conclusion

The implemented unit and integration tests provide evidence that the main Person A components operate according to their defined behavior.

Further testing is required to assess broader system integration, performance, and production readiness.

---

## 13. Limitations and Future Improvements

### 13.1 Current Limitations

Although the Person A components have been implemented and tested, several limitations remain.

**Machine Learning limitations**

- The ML dataset contains only 21 positive KEV examples.
- The target dataset is highly imbalanced.
- The experiments are exploratory and do not establish reliable prediction of future exploitation.
- EPSS is an exploitation-related feature and contributes strongly to the observed model performance.

**Risk Scoring limitations**

- The risk score is a custom prioritization index, not a calibrated probability.
- The score depends on the availability and quality of CVSS and EPSS information.
- KEV membership is used as an additional prioritization signal, but absence from KEV does not prove that a vulnerability has never been exploited.

**LLM limitations**

- Generated explanations may contain inaccurate or unsupported statements.
- Additional validation is needed to improve factual consistency.
- Structured vulnerability information must remain the source of truth for technical findings.

**Security Testing limitations**

- The current executor supports only `PACKAGE_VERSION_CHECK`.
- It performs local package metadata checks rather than full security testing.
- It does not execute exploits or perform penetration testing.
- Version comparison may return `UNKNOWN` when the available range information is insufficient or unsupported.

**Integration limitations**

- The current Person A workflow has been validated through unit tests and integration scripts.
- Broader integration with the complete application and Person B components requires additional validation.

### 13.2 Future Improvements

Several improvements could extend the current implementation.

1. **Improve ML evaluation:** collect more labeled examples and evaluate models using additional validation strategies.
2. **Improve risk assessment:** investigate additional vulnerability intelligence signals and refine the prioritization methodology.
3. **Improve LLM reliability:** strengthen prompts, structured output validation, and factual consistency checks.
4. **Extend security testing:** support additional safe verification methods and package ecosystems.
5. **Improve test reporting:** provide clearer execution evidence and traceability for each generated test.
6. **Improve system integration:** connect the Person A components with the persistence, streaming, and dashboard components.
7. **Prepare cloud deployment:** adapt the components to a controlled AWS-based environment when the application architecture is ready.

### 13.3 Final Conclusion

The Person A implementation provides the vulnerability intelligence and controlled security analysis foundation of VulnGuard AI.

It combines data ingestion, preprocessing, feature engineering, exploratory machine learning, risk scoring, vulnerability analysis, LLM-based explanations, security test generation, human approval, and controlled package-version verification.

The resulting workflow demonstrates how vulnerability information can be transformed into prioritized findings and reviewed security test plans.

The implementation establishes a foundation for further integration and development toward a complete AI-assisted vulnerability management system.