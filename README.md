I'll create a comprehensive markdown file for the GitHub repository based on the information provided in the documents. Let me analyze the content and structure first.

# ProtectAI AWS Toolkit

A comprehensive toolkit for securing AI models on AWS Bedrock through integration with Protect AI's security solutions.

## Overview

This repository provides end-to-end security tooling for AI models running on Amazon Bedrock, leveraging Guardian (Model Scanning)and Recon (AI Red Teaming) from Protect AI. The toolkit enables organizations to implement robust security measures throughout the LLM lifecycle, from downloading model artifacts to deployment.

## Key Components


### 1. Guardian - ML Model Security Scanning

Guardian secures your machine learning ecosystem by validating models for vulnerabilities before deployment:

- **Guardian Gateway**: Creates a secure perimeter around third-party model access by intercepting requests to sources like Hugging Face Hub
- **Guardian Scanner**: Deployed within your infrastructure to provide a dedicated API endpoint for validating internal first-party models
- **Vulnerability Detection**: Identifies security issues like deserialization vulnerabilities in model files

### 2. Recon - AI Red Teaming

Recon proactively identifies security vulnerabilities in your LLMs by simulating advanced attacks and generating comprehensive security reports:

- **Attack Simulation**: Automates the testing of models against common attack vectors including prompt injection, jailbreaking, adversarial suffixes, and evasion techniques
- **Threat Analysis**: Provides detailed analytics about model vulnerabilities and their severity
- **Guardrail Generation**: Leverages attack insights to create effective security guardrails


## Notebooks and Tools

### 1. Secure Model Import

`Secure Model Import Using Protect AI Guardian.ipynb` demonstrates how to securely import models to Amazon Bedrock:

- Uses Guardian Gateway to safely download models from Hugging Face
- Performs security scans during transfer to identify vulnerabilities
- Implements Guardian Scanner to validate models stored in S3
- Demonstrates vulnerability detection and remediation
- Completes the import process to AWS Bedrock


### 2. Amazon Bedrock Guardrails Generation

The repository includes Jupyter notebooks for automating the creation of AWS Bedrock Guardrails using threat intelligence from Recon:

- `Recon_Protect AI Bedrock Guardrails.ipynb`: 
  - Analyzes attack patterns from Recon security scans
  - Generates AI-powered enhanced guardrails based on detected threats
  - Implements and tests guardrails using AWS Bedrock API
  - Evaluates guardrail effectiveness against threat prompts

### 3. Helper Modules

The toolkit includes Python utility modules for streamlining security operations:

- `recon_helper_functions.py`: Functions for threat data processing, LLM-powered attack analysis, and guardrail testing
- Additional scripts for creating, evaluating, and implementing security measures

## Example Workflows

### Secure Model Import Workflow

1. Install required packages and configure parameters
2. Download model from Hugging Face through Guardian Gateway
3. Upload model to S3 storage
4. Use Guardian Scanner to detect vulnerabilities
5. Take action on detected vulnerabilities and re-scan
6. Create and monitor custom model import job in Amazon Bedrock
7. Set up proper tokenization and test the imported model

### Guardrail Development Workflow

1. Extract attack data from Protect AI's Recon system
2. Analyze threats to identify patterns and vulnerabilities
3. Generate AI-based security guardrails leveraging threat intelligence
4. Implement the guardrails in AWS Bedrock
5. Test guardrail effectiveness against known threats

## Results and Reports

The toolkit generates detailed security reports:

- **Guardrail Effectiveness Report**: Shows performance metrics of implemented guardrails against real attacks
- **Threat Analysis Reports**: Provides comprehensive analysis of attack patterns, techniques, and recommended mitigations

## Getting Started

### Prerequisites

- An AWS account with access to Amazon Bedrock
- Appropriate IAM roles and permissions for Bedrock and Amazon S3
- A S3 bucket prepared to store custom models
- Access to Protect AI Guardian and Recon (reach out to the [Protect AI team](https://protectai.com/contact-sales))

### Installation

1. Clone this repository
2. Install required dependencies
3. Configure AWS credentials and environment variables
4. Follow notebook instructions for specific tasks

## Key Benefits

- **Zero-Trust Security**: Implement a security-first approach for all AI models
- **Continuous Validation**: Scan models throughout their lifecycle whenever moved or modified
- **Automated Guardrails**: Convert threat intelligence into effective defense mechanisms
- **Comprehensive Testing**: Evaluate model security against diverse attack vectors
- **Proactive Protection**: Identify and remediate vulnerabilities before production deployment

## License
This project is licensed under the AGPL-3.0 license