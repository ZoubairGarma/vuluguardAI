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
- LangGraph / Hugging Face
- AWS (future deployment)

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

## Project Status

- [x] Initial repository structure
- [ ] Kafka local setup
- [ ] Producer and Consumer
- [ ] Streamlit interface
- [ ] Vulnerability enrichment
- [ ] ML model
- [ ] AI agents
- [ ] Human approval
- [ ] Test execution
- [ ] AWS deployment