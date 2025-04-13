# Agent Purple – Development Guide

## Table of Contents
- [Project Overview](#project-overview)
- [System Architecture](#system-architecture)
- [Key Development Principles](#key-development-principles)
- [Project Structure](#project-structure)
- [Development Workflow](#development-workflow)
  - [1. Initial Repository Setup](#1-initial-repository-setup)
  - [2. Establish Project Structure](#2-establish-project-structure)
  - [3. Implement Utility Modules](#3-implement-utility-modules)
  - [4. Develop Agent Modules](#4-develop-agent-modules)
  - [5. Implement Orchestration](#5-implement-orchestration)
  - [6. Create Frontend Interface](#6-create-frontend-interface)
  - [7. Testing and Refinement](#7-testing-and-refinement)
  - [8. Deployment](#8-deployment)
  - [9. Final Submission](#9-final-submission)
- [Key Technologies and Integration](#key-technologies-and-integration)
  - [MITRE ATT&CK® and ATLAS Integration](#mitre-attack-and-atlas-integration)
  - [GitHub MCP Server Integration](#github-mcp-server-integration)
  - [AutoGen Framework for Agent Orchestration](#autogen-framework-for-agent-orchestration)
  - [DSPy for Modular AI Development](#dspy-for-modular-ai-development)
- [Agent Implementations](#agent-implementations)
  - [Red Team Agent](#red-team-agent)
  - [Motivation Analysis Agent](#motivation-analysis-agent)
  - [Blue Team Agent](#blue-team-agent)
- [Security and Best Practices](#security-and-best-practices)
  - [Input Validation and Security](#input-validation-and-security)
  - [Code Quality and Documentation](#code-quality-and-documentation)
  - [Version Control Best Practices](#version-control-best-practices)

This document provides comprehensive guidance for implementing "Agent Purple," a multi-agent system that analyzes GitHub repositories for vulnerabilities in AI-enabled systems. It covers architecture details, step-by-step development instructions, and best practices for creating a robust, modular, and secure solution.

---

## Project Overview

Agent Purple is a multi-agent system designed to autonomously analyze GitHub repositories for vulnerabilities in AI-enabled systems. The system assists developers and security teams by identifying vulnerabilities, understanding their root causes, and suggesting actionable fixes.

### Target Audience
- Software developers working on AI systems
- Security researchers
- Organizations focused on secure AI development

### Core Functionality
The system comprises multiple autonomous agents that work together:

1. **Red Team Agent:** Scans code (using the OpenAI API) for vulnerabilities and maps them to MITRE ATT&CK/ATLAS reference IDs
2. **Motivation Analysis Agent:** Analyzes each vulnerability to infer possible developer motivations behind the code issues
3. **Blue Team Agent:** Suggests code-level and conceptual fixes for the identified vulnerabilities
4. **Orchestration Layer:** Uses AutoGen to coordinate the agents
5. **Frontend:** A Gradio web interface presents the final Markdown report

### System Workflow
1. Clone the target repository using the GitHub MCP client
2. Use the Red Team Agent to scan for vulnerabilities
3. Pass the results to the Motivation Analysis Agent for root cause analysis
4. Use the Blue Team Agent to suggest fixes
5. Compile the results into a Markdown report
6. Display the report via the Gradio frontend

---

## Key Development Principles

To ensure a high-quality implementation, the following principles should be followed:

- **Modularity:** Use self-contained Python modules for each component
- **Standards Compliance:** Adhere to PEP8, SOLID principles, and clear error handling
- **Testing:** Test each module individually and perform integration testing
- **Incremental Development:** Commit progress incrementally with clear, descriptive messages
- **Secure Secrets Management:** Store API keys securely in a `.env` file and do not commit them to version control
- **Logging and Monitoring:** Implement logging for debugging and operational insights
- **Documentation:** Maintain up-to-date documentation for all modules and workflows

---

## Project Structure

The final directory structure should look like this:

```
agent_purple/
├── data/
│   ├── mitre_attack/        # Latest MITRE ATT&CK data
│   └── mitre_atlas/         # Latest MITRE ATLAS data
├── agents/
│   ├── red_team_agent.py                # Vulnerability scanning agent using OpenAI API
│   ├── motivation_analysis_agent.py     # Developer motivation inference agent
│   └── blue_team_agent.py               # Remediation suggestion agent
├── frontend/
│   └── app.py                           # Gradio-based frontend application
├── utils/
│   ├── github_mcp_client.py             # GitHub repository interaction utility (via Git operations)
│   └── data_fetcher.py                  # Fetches MITRE ATT&CK/ATLAS data (using TAXII, requests, and pyyaml)
├── tests/                               # Unit and integration tests
├── .env                                 # Securely stores API keys (e.g., OPENAI_API_KEY, GITHUB_PERSONAL_ACCESS_TOKEN)
├── .gitignore                           # Specifies files/folders to ignore in Git (e.g., .env, __pycache__)
├── main.py                              # Orchestration of agents and report compilation (with AutoGen integration)
├── environment.yml                      # Conda environment definition (optional alternative to requirements.txt)
├── requirements.txt                     # List of pip dependencies (if not using environment.yml)
└── README.md                            # Project overview, setup instructions, and usage guidelines
```

---

## Development Workflow

### 1. Initial Repository Setup

1. **Create GitHub Repository**  
   - Create a new GitHub repository (e.g., `agent_purple`)
   - Clone the repository locally

2. **Setup Conda Environment & Base Dependencies**  
   Instead of using the native Python virtual environment, create and activate a Conda environment:
   ```bash
   conda create -n agent_purple python=3.12
   conda activate agent_purple
   ```

3. **Manage Dependencies**  
   Create an `environment.yml` file for reproducibility:

   ```yaml
   name: agent_purple
   channels:
     - defaults
     - conda-forge
   dependencies:
     - python=3.12
     - pip
     - pip:
         - openai==0.27.0
         - autogen==0.1.0         # Replace with the latest version
         - gradio==3.30.0
         - requests==2.28.2
         - pyyaml==6.0
         - stix2==3.1.1
         - taxii2-client==0.2.4
         - dspy==1.0.0            # For modular AI system development
   ```

   Create the environment from this file by running:
   ```bash
   conda env create -f environment.yml
   conda activate agent_purple
   ```

4. **Setup Secure API Key Management**  
   - Create a file named `.env` (make sure it is listed in `.gitignore`)
   - Add your API keys there:
     ```ini
     OPENAI_API_KEY=your_openai_api_key
     GITHUB_PERSONAL_ACCESS_TOKEN=your_github_personal_access_token
     ```
   - In your Python code, load these keys using packages like `python-dotenv`:
     ```python
     from dotenv import load_dotenv
     import os

     load_dotenv()  # take environment variables from .env.
     openai_api_key = os.getenv("OPENAI_API_KEY")
     github_pat = os.getenv("GITHUB_PERSONAL_ACCESS_TOKEN")
     ```

5. **Create/Edit `.gitignore` File**  
   Add the following content to `.gitignore`:
   ```
   # Byte-compiled / optimized / DLL files
   __pycache__/
   *.py[cod]
   *$py.class

   # Virtual environments
   /venv/
   /env/
   /.conda/

   # Environment variable files
   .env

   # Jupyter Notebook checkpoints
   .ipynb_checkpoints/

   # OS-specific files
   .DS_Store
   Thumbs.db
   ```

6. **Add Basic README.md**  
   - Create a README with project overview, purpose, and setup instructions including the Conda and .env setup

7. **Initial Commit**  
   ```
   git add .
   git commit -m "chore: Initialize repository with Conda environment, .gitignore, and secure key storage setup"
   git push origin main
   ```

### 2. Establish Project Structure

1. **Create Directory Layout and Placeholder Files:**  
   - Create folders: `data/`, `agents/`, `frontend/`, `utils/`, `tests/`
   - Create empty files for each module:
     - `agents/red_team_agent.py`
     - `agents/motivation_analysis_agent.py`
     - `agents/blue_team_agent.py`
     - `frontend/app.py`
     - `utils/data_fetcher.py`
     - `utils/github_mcp_client.py`
     - `main.py`

2. **Commit Changes:**  
   ```
   git add .
   git commit -m "feat: Create initial project directory structure and placeholder files"
   git push origin main
   ```

### 3. Implement Utility Modules

1. **Develop `utils/data_fetcher.py`:**  
   - Write functions to retrieve MITRE ATT&CK data via TAXII and MITRE ATLAS data (using `requests`, `pyyaml`, and `stix2`)
   - Test the functions locally to verify that data is fetched and parsed correctly

   **Commit Message:**  
   ```
   feat(utils): Add data_fetcher to retrieve MITRE ATT&CK and ATLAS data
   ```

2. **Develop `utils/github_mcp_client.py`:**  
   - Implement functionality to clone repositories, list files, and read file contents using the official GitHub MCP Server
   - Test by cloning a sample repository

   **Commit Message:**  
   ```
   feat(utils): Add GitHubMCPClient for repository cloning and file management
   ```

### 4. Develop Agent Modules

1. **Implement `agents/red_team_agent.py`:**  
   - Write the function that uses the OpenAI API to analyze code snippets for vulnerabilities and output results in JSON format
   - Test with sample code snippets

   **Commit Message:**  
   ```
   feat(agents): Implement red_team_agent for vulnerability scanning using OpenAI API
   ```

2. **Implement `agents/motivation_analysis_agent.py`:**  
   - Develop the module to analyze vulnerabilities and infer developer motivations
   - Use sample JSON input from the red team and verify the output

   **Commit Message:**  
   ```
   feat(agents): Implement motivation_analysis_agent to infer developer motivations
   ```

3. **Implement `agents/blue_team_agent.py`:**  
   - Code the function that suggests remediation fixes and outputs recommendations in JSON format
   - Validate using sample vulnerabilities

   **Commit Message:**  
   ```
   feat(agents): Add blue_team_agent to generate remediation recommendations
   ```

### 5. Implement Orchestration

1. **Set Up AutoGen Orchestration in `main.py`:**  
   - Integrate AutoGen to coordinate the agents by wrapping each agent function into an AutoGen `AssistantAgent` object
   - Example (simplified):
     ```python
     from autogen import AssistantAgent, Conversation

     red_team = AssistantAgent("RedTeam", function=red_team_agent_function)
     motivation_agent = AssistantAgent("MotivationAgent", function=motivation_analysis_agent_function)
     blue_team = AssistantAgent("BlueTeam", function=blue_team_agent_function)

     conversation = Conversation(agents=[red_team, motivation_agent, blue_team])
     conversation.start()
     ```

   **Commit Message:**  
   ```
   feat(main): Integrate AutoGen orchestration for multi-agent communication and report compilation
   ```

2. **Assemble the Report:**  
   - Use `GitHubMCPClient` to clone the repo, iterate over files, run agents, and compile a Markdown report

   **Commit Message:**  
   ```
   feat(main): Add orchestration logic to iterate through repo files and compile security report
   ```

### 6. Create Frontend Interface

1. **Implement `frontend/app.py`:**  
   - Create a Gradio interface to enter a repo URL and return the generated Markdown report using the orchestration backend

   **Commit Message:**  
   ```
   feat(frontend): Implement Gradio-based UI for repository assessment and report display
   ```

2. **Test the Interface:**  
   - Ensure successful launch and functionality

### 7. Testing and Refinement

1. **Test End-to-End Flow:**  
   - Validate complete flow via CLI and frontend

   **Commit Message:**  
   ```
   fix: Resolve integration issues between agents and improve error handling during repo analysis
   ```

2. **Documentation and Cleanup:**  
   - Refactor code, update README, and comment functions for clarity

   **Commit Message:**  
   ```
   docs: Update README and add inline documentation for clarity
   ```

3. **Add Unit Tests:**  
   - Add tests for utility functions or JSON structure

   **Commit Message:**  
   ```
   test: Add basic unit tests for utility modules and agent functions
   ```

### 8. Deployment

1. **Local Deployment:**  
   - Run the Gradio app locally using:
     ```bash
     python frontend/app.py
     ```

2. **Cloud Deployment:**  
   - Use platforms like AWS, Azure, or Heroku for deployment
   - Ensure all environment variables are securely configured

   **Commit Message:**  
   ```
   chore: Add deployment instructions for local and cloud environments
   ```

### 9. Final Submission

1. **Final Cleanup:**  
   - Remove debug code and ensure submission readiness

   **Commit Message:**  
   ```
   chore: Final code cleanup and project review before submission
   ```

2. **Push and Tag Final Release:**  
   ```bash
   git tag v1.0
   git push origin v1.0
   ```

---

## Key Technologies and Integration

### MITRE ATT&CK and ATLAS Integration

MITRE ATT&CK® and MITRE ATLAS are critical resources for understanding and addressing vulnerabilities in AI-enabled systems.

#### MITRE ATT&CK® Framework

MITRE ATT&CK® is a globally accessible knowledge base of adversary tactics and techniques based on real-world observations. It provides a structured framework for understanding adversary operations and mapping vulnerabilities to specific tactics and techniques.

**Integration in Agent Purple:**
- **Red Team Agent:** Maps identified vulnerabilities to specific ATT&CK tactics and techniques
- **Blue Team Agent:** Suggests mitigations aligned with the identified tactics and techniques

**Implementation:**
```python
# First install the mitreattack-python library
# pip install mitreattack-python

from utils.data_fetcher import fetch_mitre_attack_data

attack_data = fetch_mitre_attack_data()

def map_to_mitre_attack(vulnerability):
    # Logic to map vulnerability to MITRE ATT&CK®
    return mapped_tactic, mapped_technique
```

#### MITRE ATLAS Framework

MITRE ATLAS (Adversarial Threat Landscape for Artificial-Intelligence Systems) is a knowledge base focused on adversarial threats to AI systems. It provides a framework for understanding and mitigating risks specific to AI.

**Integration in Agent Purple:**
- **Red Team Agent:** Analyzes vulnerabilities in AI systems with a focus on AI-specific threats
- **Blue Team Agent:** Proposes AI-specific remediation strategies

**Implementation:**
```python
# ATLAS data is stored in a YAML file and can be accessed directly
from utils.data_fetcher import fetch_mitre_atlas_data

atlas_data = fetch_mitre_atlas_data()

def analyze_with_mitre_atlas(vulnerability):
    # Logic to analyze vulnerability using MITRE ATLAS
    return analysis_result
```

#### Data Fetcher Implementation

The `utils/data_fetcher.py` module provides functions to retrieve and work with both MITRE ATT&CK and ATLAS data:

1. **For MITRE ATT&CK:**
   - Uses the official `mitreattack-python` library to fetch data
   - Provides functions to query techniques, tactics, and other ATT&CK objects
   - Implements local caching to reduce API calls
   - Falls back to direct STIX data download when the library is unavailable

2. **For MITRE ATLAS:**
   - Retrieves the ATLAS.yaml file from the official GitHub repository
   - Parses the YAML data to access tactics, techniques, and case studies
   - Implements local caching for offline use

3. **Key Functions:**
   - `fetch_mitre_attack_data(domain, version)`: Fetches ATT&CK data for enterprise, mobile, or ICS domains
   - `fetch_mitre_atlas_data()`: Retrieves MITRE ATLAS data from GitHub
   - `get_attack_techniques()`, `get_atlas_techniques()`: Extract techniques from the data
   - `map_vulnerability_to_attack()`, `map_vulnerability_to_atlas()`: Map vulnerabilities to the frameworks

4. **Error Handling and Reliability:**
   - Graceful degradation when network or resources are unavailable
   - Comprehensive logging for operations and errors
   - Automatic fallback to cached data when fresh data cannot be retrieved

#### Best Practices
- Keep data updated regularly
- Use structured data formats for mapping vulnerabilities
- Document findings in detail in the final report
- Implement caching to reduce external API calls

### GitHub MCP Server Integration

The Official GitHub MCP Server enables seamless interaction with GitHub repositories for the Agent Purple project.

#### Setting Up the MCP Server

1. **Prerequisites:**
   - Docker installation
   - GitHub Personal Access Token with appropriate permissions

2. **Running the MCP Server:**
   ```bash
   docker run -i --rm -e GITHUB_PERSONAL_ACCESS_TOKEN=your_github_personal_access_token ghcr.io/github/github-mcp-server
   ```

#### Integration with Agent Purple

The `utils/github_mcp_client.py` module interacts with the MCP server to clone repositories, list files, and fetch file contents:

```python
from utils.github_mcp_client import GitHubMCPClient

client = GitHubMCPClient()
repo_url = "https://github.com/example/repo"
client.clone_repository(repo_url)
files = client.list_files()
```

#### Best Practices
- Store the GitHub token securely in the `.env` file
- Implement proper error handling for MCP interactions
- Monitor MCP server logs for errors or warnings

### AutoGen Framework for Agent Orchestration

AutoGen is a framework developed by Microsoft for creating multi-agent AI applications. In Agent Purple, it coordinates interactions between the Red Team, Motivation Analysis, and Blue Team agents.

#### Key Features of AutoGen

- **Layered Design:** Core API, AgentChat API, and Extensions API for flexibility
- **Developer Tools:** AutoGen Studio for prototyping and AutoGen Bench for evaluation
- **Rich Ecosystem:** Regular updates and community support

#### Using AutoGen for Orchestration

1. **Define Agent Functions:**
   ```python
   def red_team_agent_function(input_data):
       # Analyze code for vulnerabilities
       return vulnerabilities
   ```

2. **Wrap Functions into AutoGen Agents:**
   ```python
   from autogen import AssistantAgent
   
   red_team = AssistantAgent("RedTeam", function=red_team_agent_function)
   ```

3. **Create a Conversation Flow:**
   ```python
   from autogen import Conversation
   
   conversation = Conversation(agents=[red_team, motivation_agent, blue_team])
   conversation.start(input_data=repository_data)
   ```

#### Best Practices
- Keep each agent's function focused on a single responsibility
- Implement error handling within each agent function
- Use logging to track data flow and debug issues
- Test each agent function independently before integration

### DSPy for Modular AI Development

DSPy (Declarative Self-improving Python) is a framework for programming language models rather than relying on prompt engineering. It enables building modular AI systems and optimizing prompts and weights.

#### Use Cases in Agent Purple

1. **Modular Agent Definition:**
   ```python
   import dspy
   
   red_team_module = dspy.Predict("code_snippet -> vulnerabilities: list")
   ```

2. **Prompt Optimization:**
   ```python
   from dspy import MIPROv2
   
   optimizer = MIPROv2(metric=dspy.evaluate.answer_exact_match)
   optimized_red_team = optimizer.compile(red_team_module, trainset=train_data)
   ```

3. **Module Composition:**
   ```python
   from dspy import ChainOfThought
   
   pipeline = ChainOfThought([
       red_team_module,
       motivation_module,
       blue_team_module
   ])
   ```

#### Best Practices
- Define each agent as a separate DSPy module
- Use optimizers to refine prompts and weights
- Document the input/output behavior of each module
- Test modules independently before integration

---

## Agent Implementations

### Red Team Agent

The Red Team Agent is responsible for scanning code repositories to identify vulnerabilities in AI-enabled systems. It leverages the OpenAI API to analyze code snippets and maps identified issues to the MITRE ATT&CK and ATLAS frameworks.

**Key Responsibilities:**
- Analyze code snippets for security vulnerabilities
- Identify AI-specific security issues
- Map vulnerabilities to MITRE ATT&CK/ATLAS reference IDs
- Output structured data about identified vulnerabilities

**Implementation Guidelines:**
1. Use the OpenAI API with appropriate prompts for code analysis
2. Implement caching to minimize redundant API calls
3. Structure the output in a consistent JSON format
4. Include severity ratings for each vulnerability

### Motivation Analysis Agent

The Motivation Analysis Agent examines vulnerabilities identified by the Red Team Agent to infer the developer's thought process or intent behind implementing potentially vulnerable code.

**Key Objectives:**
- Understand developer intent behind vulnerable code
- Provide context for why vulnerabilities might have been introduced
- Aid in root cause analysis and prioritization of fixes

**Integration with the Workflow:**
1. Receives a list of vulnerabilities identified by the Red Team Agent
2. Uses NLP and contextual analysis to infer motivations
3. Produces a report detailing the inferred motivations for each vulnerability

**Example Use Case:**
- **Vulnerability:** Hardcoded credentials found in the code
- **Inferred Motivation:** Developer might have hardcoded credentials for quick testing or due to lack of awareness about secure credential management

### Blue Team Agent

The Blue Team Agent suggests remediation strategies for the vulnerabilities identified by the Red Team Agent, taking into account the developer motivations analyzed by the Motivation Analysis Agent.

**Key Responsibilities:**
- Generate code-level fixes for identified vulnerabilities
- Provide conceptual guidance for addressing systemic issues
- Prioritize recommendations based on severity and impact
- Link suggestions to industry best practices

**Implementation Guidelines:**
1. Use the OpenAI API to generate code fixes
2. Structure recommendations in a clear, actionable format
3. Include both quick fixes and long-term remediation strategies
4. Reference relevant security standards or guidelines

---

## Security and Best Practices

### Input Validation and Security

To prevent exploitation and ensure the security of the Agent Purple system, implement robust user input validation across all components.

#### Key Principles for Input Validation

1. **Sanitize Inputs:**
   ```python
   def sanitize_repo_url(url):
       # Remove potentially harmful characters
       return re.sub(r'[;&|"`\'\\]', '', url)
   ```

2. **Validate Input Format:**
   ```python
   import gradio as gr

   def validate_repo_url(repo_url):
       if not repo_url.startswith("https://github.com/"):
           raise ValueError("Invalid GitHub repository URL.")
       return repo_url

   gr.Interface(fn=validate_repo_url, inputs="text", outputs="text").launch()
   ```

3. **Implement Defense in Depth:**
   - Validate at multiple levels (frontend, backend, agents)
   - Provide clear error messages
   - Log invalid input attempts
   - Regularly update validation logic

### Code Quality and Documentation

Maintain high code quality and comprehensive documentation throughout the project:

1. **Type Hints and Docstrings:**
   ```python
   def analyze_vulnerability(code_snippet: str) -> dict:
       """
       Analyzes a code snippet for security vulnerabilities.
       
       Args:
           code_snippet: String containing the code to analyze
           
       Returns:
           Dictionary containing identified vulnerabilities
       """
       # Implementation
   ```

2. **Use Linting and Formatting Tools:**
   - Use `flake8` for linting
   - Use `black` for consistent code formatting

3. **Comprehensive Documentation:**
   - Update README.md with setup and usage instructions
   - Include inline documentation for all functions
   - Document APIs and data formats

### Version Control Best Practices

Follow these version control best practices for a clean and organized repository:

1. **Commit Often with Clear Messages:**
   - Use conventional commits format (feat, fix, docs, etc.)
   - Include scope and clear description

2. **Branch Strategy:**
   - Use feature branches for new functionality
   - Use bugfix branches for fixes
   - Merge via pull requests after review

3. **Code Review Process:**
   - Review all changes before merging
   - Use pull request templates
   - Ensure tests pass before merging

---

*End of DEVELOPMENT_GUIDE.md*