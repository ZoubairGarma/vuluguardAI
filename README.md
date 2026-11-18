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

## AI explanations

Each finding's explanation has two parts:

- **Verified sections, written by code.** Risk score, CVSS, EPSS, KEV status,
  affected packages, installed and fixed versions, and recommendations are
  rendered directly from the analyzer output, so they cannot be misquoted.
- **AI narrative, written by the LLM.** A short JSON answer: a plain-language
  summary of the advisory, the impact the advisory states, exposure
  conditions, and limitations of the advisory text. The prompt contains no
  scores or versions. The narrative is fact-checked; numbers that do not
  appear in the source text are rejected. A failed narrative gets one repair
  attempt and is withheld if it still fails, while the verified sections are
  always shown.

The model and its settings are read from `.env` (`OLLAMA_MODEL`,
`OLLAMA_NUM_CTX`, `OLLAMA_TEMPERATURE`, `OLLAMA_SEED`, `OLLAMA_TIMEOUT`,
`OLLAMA_BASE_URL`). Keep `OLLAMA_NUM_CTX` at 8192 or more: when a prompt does
not fit, Ollama silently drops its beginning.

### Compare models

After running a few scans, compare models on the stored findings:

```powershell
ollama pull qwen2.5:3b
python -m src.agents.evaluate_llm --models llama3.2:3b,qwen2.5:3b --limit 20
```

The script prints the share of narratives accepted (first try and after
repair), withheld, and the average time per finding, and saves full results in
`reports/`. Use `--findings file.json` to evaluate a list of findings instead
of the database.
