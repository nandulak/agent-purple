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
  - [GitHub Client Integration](#github-client-integration)
  - [AutoGen Framework for Agent Orchestration](#autogen-framework-for-agent-orchestration)
  - [DSPy for Modular AI Development](#dspy-for-modular-ai-development)
- [Agent Implementations](#agent-implementations)
  - [Red Team Agent](#red-team-agent)
  - [Motivation Analysis Agent](#motivation-analysis-agent)
  - [Blue Team Agent](#blue-team-agent)
- [Testing Infrastructure](#testing-infrastructure)
  - [Unit Testing](#unit-testing)
  - [AI-Specific Testing](#ai-specific-testing)
  - [Integration Testing](#integration-testing)
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

1. **Red Team Agent:** Scans code (using the OpenAI GPT-4o API) for vulnerabilities and maps them to MITRE ATT&CK/ATLAS reference IDs
2. **Motivation Analysis Agent:** Analyzes each vulnerability to infer possible developer motivations behind the code issues
3. **Blue Team Agent:** Suggests code-level and conceptual fixes for the identified vulnerabilities
4. **Orchestration Layer:** Uses AutoGen to coordinate the agents
5. **Frontend:** A Gradio web interface presents the final Markdown report

### System Workflow
1. Clone the target repository using the GitHub client
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
│   ├── red_team_agent.py                # Vulnerability scanning agent using OpenAI GPT-4o API
│   ├── motivation_analysis_agent.py     # Developer motivation inference agent
│   └── blue_team_agent.py               # Remediation suggestion agent
├── frontend/
│   └── app.py                           # Gradio-based frontend application
├── utils/
│   ├── github_client.py                 # GitHub repository interaction utility (via direct Git operations)
│   └── data_fetcher.py                  # Fetches MITRE ATT&CK/ATLAS data (using TAXII, requests, and pyyaml)
├── tests/                               # Unit and integration tests
│   ├── test_red_team_agent.py           # General vulnerability tests
│  
│   └── test_red_team_integration.py     # Real-world AI repository testing
├── test_results/                        # Test output and reports
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
         - openai>=1.0.0  # Updated to support GPT-4o
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
   
   # Test results
   /test_results/

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
   - Create folders: `data/`, `agents/`, `frontend/`, `utils/`, `tests/`, `test_results/`
   - Create empty files for each module:
     - `agents/red_team_agent.py`
     - `agents/motivation_analysis_agent.py`
     - `agents/blue_team_agent.py`
     - `frontend/app.py`
     - `utils/data_fetcher.py`
     - `utils/github_client.py`
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

2. **Develop `utils/github_client.py`:**  
   - Implement functionality to clone repositories, list files, and read file contents using direct Git operations
   - Test by cloning a sample repository

   **Commit Message:**  
   ```
   feat(utils): Add GitHubClient for repository cloning and file management
   ```

### 4. Develop Agent Modules

1. **Implement `agents/red_team_agent.py`:**  
   - Write the function that uses the OpenAI API with GPT-4o to analyze code snippets for vulnerabilities and output results in JSON format
   - Implement AI-specific vulnerability detection
   - Create framework mapping to MITRE ATT&CK and ATLAS
   - Test with sample code snippets

   **Commit Message:**  
   ```
   feat(agents): Implement red_team_agent for vulnerability scanning using OpenAI GPT-4o API
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
   - Use `GitHubClient` to clone the repo, iterate over files, run agents, and compile a Markdown report

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

1. **Develop Comprehensive Test Suite:**  
   - Create general test file: `tests/test_red_team_agent.py`
   - Create AI-specific test file: `tests/test_red_team_ai_vulnerabilities.py`
   - Create integration test file: `tests/test_red_team_integration.py`

   **Commit Message:**  
   ```
   feat(tests): Add comprehensive test suite for Red Team Agent
   ```

2. **Test End-to-End Flow:**  
   - Validate complete flow via CLI and frontend

   **Commit Message:**  
   ```
   fix: Resolve integration issues between agents and improve error handling during repo analysis
   ```

3. **Documentation and Cleanup:**  
   - Refactor code, update README, and comment functions for clarity

   **Commit Message:**  
   ```
   docs: Update README and add inline documentation for clarity
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

### GitHub Client Integration

The GitHub client enables seamless interaction with GitHub repositories for the Agent Purple project.

#### Integration with Agent Purple

The `utils/github_client.py` module interacts with GitHub repositories to clone repositories, list files, and fetch file contents:

```python
from utils.github_client import GitHubClient

client = GitHubClient()
repo_url = "https://github.com/example/repo"
client.clone_repository(repo_url)
files = client.list_files()
```

#### Best Practices
- Store the GitHub token securely in the `.env` file
- Implement proper error handling for Git operations
- Monitor logs for errors or warnings

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

The Red Team Agent is responsible for scanning code repositories to identify vulnerabilities in AI-enabled systems. It leverages the OpenAI API with GPT-4o model to analyze code snippets and maps identified issues to the MITRE ATT&CK and ATLAS frameworks.

**Key Responsibilities:**
- Analyze code snippets for security vulnerabilities
- Identify AI-specific security issues
- Map vulnerabilities to MITRE ATT&CK/ATLAS reference IDs
- Output structured data about identified vulnerabilities

**Implementation Guidelines:**
1. Use the OpenAI API with GPT-4o for enhanced code analysis capability
2. Implement caching to minimize redundant API calls
3. Structure the output in a consistent JSON format
4. Include severity ratings for each vulnerability

**Code Example:**
```python
@cache_api_call
def analyze_code_with_openai(code_snippet: str, file_path: str) -> Dict[str, Any]:
    """
    Use OpenAI API to analyze a code snippet for vulnerabilities.
    
    Args:
        code_snippet: String containing the code to analyze
        file_path: Path to the file being analyzed
        
    Returns:
        Dictionary containing identified vulnerabilities
    """
    try:
        # Call OpenAI API using GPT-4o model
        response = client.chat.completions.create(
            model="gpt-4o",  # Using the more powerful GPT-4o model
            messages=[
                {"role": "system", "content": "You are a security expert..."},
                {"role": "user", "content": f"Analyze this code: {code_snippet}"}
            ],
            temperature=0.2,
        )
        # Process response
        parsed_result = {
            "vulnerabilities": response.get("choices", [{}])[0].get("message", {}).get("content", "No vulnerabilities found.")
        }
        return parsed_result
    except Exception as e:
        logger.error(f"Error: {str(e)}")
        return {"vulnerabilities": []}
```

### Motivation Analysis Agent

The Motivation Analysis Agent examines vulnerabilities identified by the Red Team Agent to infer the developer's thought process or intent behind implementing potentially vulnerable code.

**Implementation Status: COMPLETED**

**Key Objectives:**
- Understand developer intent behind vulnerable code
- Provide context for why vulnerabilities might have been introduced
- Aid in root cause analysis and prioritization of fixes
- Identify patterns across multiple vulnerabilities in a repository
- Generate organizational recommendations to address systemic issues

**Implementation Details:**

The Motivation Analysis Agent is fully implemented in `agents/motivation_analysis_agent.py`. Key features include:

1. **Motivation Categories:** The agent categorizes motivations into predefined types:
   - CONVENIENCE: Developer chose to implement a solution that was simpler or faster to code
   - KNOWLEDGE_GAP: Developer lacked necessary security knowledge or awareness
   - DEADLINE_PRESSURE: Developer was under time pressure to deliver functionality
   - OVERSIGHT: Developer overlooked potential security implications
   - TESTING: Code was intended for testing purposes, not production
   - LEGACY: Code was inherited from legacy systems or practices
   - ABSTRACTION_TRUST: Developer trusted an underlying framework or library without verification

2. **Comprehensive Analysis:** For each vulnerability, the agent provides:
   - Primary motivation with detailed description
   - Secondary motivations that might apply
   - Psychological analysis of the developer thought process
   - Organizational factors that may have contributed
   - Confidence level in the analysis

3. **Pattern Recognition:** When analyzing multiple vulnerabilities, the agent identifies:
   - Distribution of motivation types across vulnerabilities
   - Common underlying factors
   - Organizational recommendations to address root causes
   - Confidence level in the pattern analysis

4. **Performance Features:**
   - Implements API call caching to reduce redundant requests
   - Provides error handling and graceful degradation
   - Includes comprehensive logging for debugging and audit purposes

5. **Testing Status:**
   - Unit tests complete and passing (tests/test_motivation_analysis_agent.py)
   - Integration tests with Red Team Agent complete and passing
   - End-to-end workflow tests complete and successful

**Example Output:**
```json
{
  "primary_motivation": {
    "category": "CONVENIENCE",
    "description": "Developer chose directly concatenating user input for simplicity",
    "category_description": "Developer chose to implement a solution that was simpler or faster to code"
  },
  "secondary_motivations": [
    {
      "category": "KNOWLEDGE_GAP",
      "description": "Developer likely unaware of SQL injection vulnerabilities"
    }
  ],
  "thought_process_analysis": "Prioritized functionality over security considerations",
  "organizational_factors": [
    "Lack of security training for developers",
    "Absence of code review processes focusing on security" 
  ],
  "confidence_level": "HIGH"
}
```

**Integration with the Workflow:**
1. Receives vulnerabilities identified by the Red Team Agent
2. Uses OpenAI GPT-4o for psychological analysis to infer motivations
3. Processes all vulnerabilities to identify patterns
4. Produces a comprehensive report with individual analyses and organizational recommendations

### Blue Team Agent

The Blue Team Agent is responsible for providing remediation strategies and code fixes for vulnerabilities identified by the Red Team Agent. It takes into account developer motivations identified by the Motivation Analysis Agent to provide more targeted and effective fixes.

#### Implementation Guidelines

1. **Core Functionality:**
   - Generate code-level fixes for specific vulnerabilities
   - Suggest conceptual recommendations to prevent similar vulnerabilities
   - Provide organizational improvements for long-term security enhancements
   - Analyze patterns across multiple vulnerabilities to create overall recommendations

2. **API Integration:**
   - Use OpenAI's GPT-4o model for generating high-quality remediation strategies
   - Implement caching to minimize redundant API calls and reduce costs
   - Handle API errors gracefully and provide fallback options

3. **Input Processing:**
   - Accept vulnerabilities from Red Team Agent in structured format
   - Incorporate motivation analyses from Motivation Analysis Agent
   - Handle various input formats (single vulnerability, vulnerability sets, repository results)

4. **Output Structure:**
   - Provide structured JSON output with:
     - Vulnerability summary and fix difficulty rating
     - Code-level fixes with descriptions and explanations
     - Conceptual recommendations for better coding practices
     - Organizational improvements for security culture
     - Relevant security standards and resources

5. **Performance Optimization:**
   - Use caching decorator for API responses
   - Implement concurrent processing for multiple vulnerabilities
   - Provide progress tracking for long-running operations

#### API Design
The `blue_team_agent.py` module should expose the following functions:

```python
def generate_vulnerability_fix(vulnerability, motivation_analysis=None): 
    """Generate a fix for a specific vulnerability with optional motivation analysis."""
    # Implementation

def generate_fixes_for_vulnerability_set(vulnerabilities, motivation_analyses=None):
    """Generate fixes for multiple vulnerabilities with optional motivation analyses."""
    # Implementation

def generate_overall_recommendations(fix_results):
    """Generate overall security recommendations based on multiple vulnerability fixes."""
    # Implementation

def process_repository_results(red_team_results, motivation_results=None):
    """Process complete repository scan results to generate comprehensive remediations."""
    # Implementation

def blue_team_agent_function(input_data, motivation_data=None):
    """Main entry point for AutoGen integration."""
    # Implementation
```

#### Testing Strategy
1. **Unit Tests:**
   - Test fix generation for individual vulnerabilities
   - Test handling of various input formats
   - Test error handling and fallback mechanisms
   - Test caching functionality

2. **Integration Tests:**
   - Test integration with Red Team Agent output
   - Test integration with Motivation Analysis Agent output
   - Test end-to-end remediation flow with real-world vulnerabilities

3. **Mock Testing:**
   - Use mock OpenAI API responses for consistent and fast testing
   - Validate prompt construction and response parsing

---

## Testing Infrastructure

### Unit Testing

The project includes comprehensive unit tests to verify the functionality of individual components:

1. **General Red Team Agent Tests (`tests/test_red_team_agent.py`):**
   - Tests the core vulnerability scanning functionality
   - Verifies mapping to MITRE frameworks
   - Tests file filtering logic
   - Tests the cache mechanism to avoid redundant API calls

2. **Running Unit Tests:**
   ```bash
   # Run the unit tests
   python -m pytest tests/test_red_team_agent.py
   ```

### AI-Specific Testing

Specialized testing for AI-specific vulnerabilities is implemented in `tests/test_red_team_ai_vulnerabilities.py`:

1. **Features Tested:**
   - Detection of AI-specific vulnerabilities (e.g., data poisoning, model evasion)
   - Mapping to MITRE ATLAS framework
   - Severity ratings for AI vulnerabilities
   
2. **Testing Setup:**
   ```python
   @pytest.fixture
   def ai_model_with_vulnerabilities():
       """Sample AI model code with intentional vulnerabilities."""
       return """
       import tensorflow as tf
       import pickle
       
       class VulnerableAIModel:
           # Intentionally vulnerable code for testing
           def load_model(self, model_path):
               with open(model_path, 'rb') as f:
                   self.model = pickle.load(f)  # Insecure deserialization
       """
   ```

3. **Running AI-Specific Tests:**
   ```bash
   python -m pytest tests/test_red_team_ai_vulnerabilities.py
   ```

### Integration Testing

The integration tests in `tests/test_red_team_integration.py` validate the Red Team Agent against real-world AI code repositories:

1. **Features Tested:**
   - End-to-end functionality with real AI repositories
   - Performance with larger codebases
   - Accuracy of vulnerability detection
   - Integration with MITRE frameworks

2. **Setting Up Integration Tests:**
   ```bash
   # Set the environment variable to run integration tests
   export RUN_INTEGRATION_TESTS=1
   
   # Run the integration tests
   python tests/test_red_team_integration.py
   ```

3. **Test Results:**
   - Integration test results are saved in the `test_results/` directory
   - Results include detected vulnerabilities and their mappings to frameworks

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