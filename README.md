# VulnGuard AI

Real-Time Open-Source Dependency Risk Intelligence
and Human-Supervised Test Automation.

## Project Overview

VulnGuard AI is a cybersecurity platform that monitors
software dependencies, identifies known vulnerabilities,
estimates risk using Machine Learning and orchestrates
AI agents to propose and execute authorized tests.

## Main Objectives

- Ingest public vulnerability data.
- Process dependency scan requests in real time.
- Identify vulnerabilities using OSV, EPSS and CISA KEV.
- Predict vulnerability risk using Machine Learning.
- Propose remediation and tests using LLM agents.
- Integrate Human-in-the-Loop approval.
- Execute tests in an isolated environment.
- Visualize results through Streamlit.

## Technologies

- Python
- Apache Kafka
- Docker
- Streamlit
- Scikit-learn
- LangGraph
- Ollama

## Local Architecture

Streamlit
    -> Kafka Producer
    -> Kafka Topic
    -> Kafka Consumer
    -> Vulnerability Analysis
    -> ML Prediction
    -> AI Agents
    -> Human Approval
    -> Test Execution
    -> Dashboard

## Local prerequisites

- Python 3.14 (the version used by the repository's current virtual environment).
- Docker Desktop with Docker Compose for local Kafka and isolated package checks.
- Ollama running locally for AI explanations. The default model is
  `llama3.2:3b` at `http://localhost:11434`.

### Python packages

The application dependencies are declared in [`requirements.txt`](requirements.txt):
Streamlit, `confluent-kafka`, `python-dotenv`, `requests`, pandas,
scikit-learn, joblib, packaging, jsonschema, CVSS, and LangGraph. Pytest is
included for development and the test suite. Install the full set with
`python -m pip install -r requirements.txt`.

### Local services

Kafka runs from the repository's Docker Compose configuration. Docker is also
used for approved package checks. Ollama provides local LLM explanations.

The package verifier downloads a pinned binary wheel from PyPI on the host,
targeting the container's Python 3.12 and Linux architecture, then installs and
inspects it in a network-disabled Docker container. The scanned
package is not imported or executed. See the [local contract and verifier
details](docs/local_contracts.md).

## Install

Run these commands from the repository root in PowerShell:

```powershell
py -3.14 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
if (-not (Test-Path .env)) { Copy-Item .env.example .env }
```

`requirements.txt` includes the application libraries and `pytest` for the test
suite. The `.env.example` file provides the local Kafka broker and topic
settings, plus a 15-minute maximum poll interval for slow LLM analysis. Adjust
`.env` if your local Kafka setup uses different values.

## Refresh derived risk data

When the processed vulnerability data or risk-scoring schema changes, rebuild
the derived CVSS and risk tables before starting the consumer. These commands
expect `data/processed/osv_severity.csv` and `data/processed/cve_features.csv`
to be present:

```powershell
python -m src.preprocessing.calculate_cvss_scores
python -m src.agents.risk_scoring
```

## Start the local application

1. Start Kafka:

   ```powershell
   docker compose up -d kafka
   docker compose ps
   ```

2. Ensure the Ollama service is running. If it is not, start it in a separate
   terminal with `ollama serve`. Download the default model if needed:

   ```powershell
   ollama pull llama3.2:3b
   ```

   Keep the Ollama service running at `http://localhost:11434`.

3. In a new terminal, activate `.venv` and start the scan consumer:

   ```powershell
   .\.venv\Scripts\Activate.ps1
   python -m src.streaming.consumer
   ```

4. In another terminal, activate `.venv` and start the Streamlit interface:

   ```powershell
   .\.venv\Scripts\Activate.ps1
   python -m streamlit run app.py
   ```

Submit a pinned `requirements.txt` through the interface. The consumer records
the analysis in SQLite and creates test plans that wait for human approval.
Approved package checks require Docker Desktop to remain available.

## Run tests

With `.venv` active, run the full local suite:

```powershell
python -m pytest -q
```

To test the real isolated Docker verifier separately, with Docker Desktop
running and host access to PyPI:

```powershell
python -c "from src.agents.docker_sandbox_verifier import DockerSandboxVerifier; print(DockerSandboxVerifier().verify('requests', '2.31.0'))"
```
