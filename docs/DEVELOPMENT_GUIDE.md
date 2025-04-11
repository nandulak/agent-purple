# Agent Purple – Development Guide

This document provides the necessary context, architecture details, and a step-by-step guide for implementing the multi-agent system that scans GitHub repositories for vulnerabilities in AI-enabled systems. It is designed to guide developers through creating each module, integrating them, and committing the work incrementally using best practices.

> **Project Overview:**  
> Agent Purple is a multi-agent system designed to autonomously analyze GitHub repositories for vulnerabilities in AI-enabled systems. The system aims to assist developers and security teams by identifying vulnerabilities, understanding their root causes, and suggesting actionable fixes. The intended audience includes developers, security researchers, and organizations focused on secure AI development.
>
> The system comprises multiple agents that work together autonomously:
> - **Red Team Agent:** Scans code (using the OpenAI API) for vulnerabilities and maps them to MITRE ATT&CK/ATLAS reference IDs.
> - **Motivation Analysis Agent:** Analyzes each vulnerability to infer possible developer motivations behind the code issues.
> - **Blue Team Agent:** Suggests code-level and conceptual fixes for the identified vulnerabilities.
> - **Orchestration:** Uses AutoGen to coordinate the agents.
> - **Frontend:** A Gradio web interface presents the final Markdown report.
> - **Repository Integration:** The Official GitHub MCP server is used to clone and analyze target repositories.
>
> **High-Level Workflow:**
> 1. Clone the target repository using the GitHub MCP client.
> 2. Use the Red Team Agent to scan for vulnerabilities.
> 3. Pass the results to the Motivation Analysis Agent for root cause analysis.
> 4. Use the Blue Team Agent to suggest fixes.
> 5. Compile the results into a Markdown report.
> 6. Display the report via the Gradio frontend.

---

## Key Principles

- **Modularity:** Use self-contained Python modules for each component.
- **Standards Compliance:** Adhere to PEP8, SOLID principles, and clear error handling.
- **Testing:** Test each module individually and perform integration testing.
- **Incremental Development:** Commit progress incrementally with clear, descriptive messages.
- **Secure Secrets Management:** Store API keys securely in a `.env` file and do not commit them to version control.
- **Logging and Monitoring:** Implement logging for debugging and operational insights.
- **Documentation:** Maintain up-to-date documentation for all modules and workflows.

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

## Step-By-Step Development Guide

### Step 1: Initial Repository Setup

1. **Create GitHub Repository**  
   - Create a new GitHub repository (e.g., `agent_purple`).
   - Clone the repository locally.

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
   ```

   Create the environment from this file by running:
   ```bash
   conda env create -f environment.yml
   conda activate agent_purple
   ```

4. **Create/Edit `.gitignore` File**  
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

5. **Securely Store API Keys**  
   - Create a file named `.env` (make sure it is listed in `.gitignore`).
   - Add your API keys there, for example:
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

6. **Commit Changes:**  
   **Commit Message:**  
   ```
   chore: Initialize repository with Conda environment, .gitignore, and secure key storage setup
   ```

7. **Add Basic README.md**  
   - Update README with project overview, purpose, and instructions including the Conda and .env setup.

   **Commit Message:**  
   ```
   docs: Add initial README with project overview and setup instructions (Conda & secure keys)
   ```

---

### Step 2: Establish Project Structure

1. **Create Directory Layout and Placeholder Files:**  
   - Create folders: `data/`, `agents/`, `frontend/`, `utils/`, `tests/`.
   - Create empty files for each module:
     - `agents/red_team_agent.py`
     - `agents/motivation_analysis_agent.py`
     - `agents/blue_team_agent.py`
     - `frontend/app.py`
     - `utils/data_fetcher.py`
     - `utils/github_mcp_client.py`
     - `main.py`

   **Commit Message:**  
   ```
   feat: Create initial project directory structure and placeholder files
   ```

---

### Step 3: Implement Utility Modules

1. **Develop `utils/data_fetcher.py`:**  
   - Write functions to retrieve MITRE ATT&CK data via TAXII and MITRE ATLAS data (using `requests`, `pyyaml`, and `stix2`).
   - Test the functions locally to verify that data is fetched and parsed correctly.

   **Commit Message:**  
   ```
   feat(utils): Add data_fetcher to retrieve MITRE ATT&CK and ATLAS data
   ```

2. **Develop `utils/github_mcp_client.py`:**  
   - Implement functionality to clone repositories, list files, and read file contents (using the official GitHub MCP Server: https://github.com/github/github-mcp-server).
   - Refer to GITHUB_MCP_README.md for details.
   - Test by cloning a sample repository.

   **Commit Message:**  
   ```
   feat(utils): Add GitHubMCPClient for repository cloning and file management
   ```

---

### Ensuring Proper User Input Validation

To prevent exploitation and ensure the security of the Agent Purple system, it is critical to implement robust user input validation. This applies to all components of the system, including the agents, orchestration, and frontend.

#### Key Principles for Input Validation

1. **Sanitize Inputs**:
   - Remove or escape any potentially harmful characters from user inputs.
   - For example, sanitize repository URLs to prevent command injection or malicious payloads.

2. **Validate Input Format**:
   - Ensure that inputs conform to the expected format and type.
   - For example, validate that a repository URL is a valid GitHub URL before processing it.

3. **Set Input Length Limits**:
   - Define maximum and minimum length constraints for inputs to prevent buffer overflow or denial-of-service attacks.

4. **Whitelist Allowed Values**:
   - Use whitelists to restrict inputs to a predefined set of acceptable values where applicable.
   - For example, restrict repository states to `open`, `closed`, or `all` when listing issues.

5. **Reject Malformed Inputs**:
   - Reject any input that does not meet the validation criteria and provide meaningful error messages to the user.

#### Implementation Guidelines

1. **Frontend Validation**:
   - Use Gradio’s built-in input validation features to enforce constraints on user inputs.
   - Example:
     ```python
     import gradio as gr

     def validate_repo_url(repo_url):
         if not repo_url.startswith("https://github.com/"):
             raise ValueError("Invalid GitHub repository URL.")
         return repo_url

     gr.Interface(fn=validate_repo_url, inputs="text", outputs="text").launch()
     ```

2. **Backend Validation**:
   - Implement additional validation in the backend to ensure inputs are safe and valid.
   - Example:
     ```python
     def validate_input(data):
         if "repo_url" not in data or not data["repo_url"].startswith("https://github.com/"):
             raise ValueError("Invalid repository URL.")
         return True

     # Example usage in main.py
     input_data = {"repo_url": "https://github.com/example/repo"}
     validate_input(input_data)
     ```

3. **Agent-Level Validation**:
   - Each agent should validate its inputs before processing them.
   - Example in the Red Team Agent:
     ```python
     def red_team_agent_function(input_data):
         if "code_snippet" not in input_data or not isinstance(input_data["code_snippet"], str):
             raise ValueError("Invalid code snippet provided.")
         # Proceed with analysis
     ```

4. **Orchestration Validation**:
   - Validate inputs at the orchestration level to ensure data passed between agents is consistent and safe.
   - Example:
     ```python
     from autogen import AssistantAgent, Conversation

     def validate_conversation_input(input_data):
         if "repo_url" not in input_data or not input_data["repo_url"].startswith("https://github.com/"):
             raise ValueError("Invalid repository URL.")

     red_team = AssistantAgent("RedTeam", function=red_team_agent_function)
     motivation_agent = AssistantAgent("MotivationAgent", function=motivation_analysis_agent_function)
     blue_team = AssistantAgent("BlueTeam", function=blue_team_agent_function)

     conversation = Conversation(agents=[red_team, motivation_agent, blue_team])
     input_data = {"repo_url": "https://github.com/example/repo"}
     validate_conversation_input(input_data)
     conversation.start(input_data=input_data)
     ```

5. **Logging and Monitoring**:
   - Log invalid input attempts for auditing and debugging purposes.
   - Example:
     ```python
     import logging

     logging.basicConfig(level=logging.INFO)

     def validate_input(data):
         if "repo_url" not in data or not data["repo_url"].startswith("https://github.com/"):
             logging.warning(f"Invalid input detected: {data}")
             raise ValueError("Invalid repository URL.")
         return True
     ```

#### Best Practices

- **Defense in Depth**: Implement validation at multiple levels (frontend, backend, agents, and orchestration).
- **Error Messages**: Provide clear and actionable error messages to users when validation fails.
- **Regular Updates**: Regularly review and update validation logic to address new threats.
- **Testing**: Write unit tests to ensure validation logic works as expected.

By following these guidelines, you can ensure that Agent Purple is resilient against exploitation and handles user inputs securely.

---

### Leveraging MITRE ATT&CK® and MITRE ATLAS

MITRE ATT&CK® and MITRE ATLAS are critical resources for understanding and addressing vulnerabilities in AI-enabled systems. Both the Red Team and Blue Team agents can utilize these frameworks to enhance their analysis and remediation capabilities.

#### Overview of MITRE ATT&CK®

MITRE ATT&CK® is a globally accessible knowledge base of adversary tactics and techniques based on real-world observations. It provides a structured framework for understanding how adversaries operate and helps in mapping vulnerabilities to specific tactics and techniques. ATT&CK is widely used in the private sector, government, and cybersecurity communities to develop threat models and methodologies.

- **Use Case in Agent Purple**:
  - **Red Team Agent**:
    - Map identified vulnerabilities to specific tactics and techniques.
    - Provide a structured understanding of potential threats.
  - **Blue Team Agent**:
    - Suggest mitigations aligned with the tactics and techniques identified by the Red Team Agent.

- **Integration Steps**:
  1. **Fetch the Latest Data**:
     - Use the `utils/data_fetcher.py` module to retrieve the latest MITRE ATT&CK® data via TAXII or other APIs.
     - Example:
       ```python
       from utils.data_fetcher import fetch_mitre_attack_data

       attack_data = fetch_mitre_attack_data()
       ```
  2. **Map Vulnerabilities**:
     - Develop a function in the Red Team Agent to map vulnerabilities to MITRE ATT&CK® tactics and techniques.
     - Example:
       ```python
       def map_to_mitre_attack(vulnerability):
           # Logic to map vulnerability to MITRE ATT&CK®
           return mapped_tactic, mapped_technique
       ```
  3. **Suggest Mitigations**:
     - Develop a function in the Blue Team Agent to suggest mitigations based on the mapped tactics and techniques.
     - Example:
       ```python
       def suggest_mitigations_with_attack(vulnerability):
           # Logic to suggest mitigations using MITRE ATT&CK®
           return mitigation_suggestions
       ```

#### Overview of MITRE ATLAS

MITRE ATLAS (Adversarial Threat Landscape for Artificial-Intelligence Systems) is a knowledge base focused on adversarial threats to AI systems. It provides a structured framework for understanding and mitigating risks specific to AI. ATLAS is designed to help organizations address the unique challenges posed by adversarial AI threats.

- **Use Case in Agent Purple**:
  - **Red Team Agent**:
    - Analyze vulnerabilities in AI systems, focusing on adversarial threats specific to AI.
  - **Blue Team Agent**:
    - Propose AI-specific remediation strategies for adversarial threats.

- **Integration Steps**:
  1. **Fetch the Latest Data**:
     - Use the `utils/data_fetcher.py` module to retrieve the latest MITRE ATLAS data.
     - Example:
       ```python
       from utils.data_fetcher import fetch_mitre_atlas_data

       atlas_data = fetch_mitre_atlas_data()
       ```
  2. **Analyze Vulnerabilities**:
     - Develop a function in the Red Team Agent to analyze vulnerabilities using MITRE ATLAS.
     - Example:
       ```python
       def analyze_with_mitre_atlas(vulnerability):
           # Logic to analyze vulnerability using MITRE ATLAS
           return analysis_result
       ```
  3. **Suggest Mitigations**:
     - Develop a function in the Blue Team Agent to suggest mitigations based on MITRE ATLAS.
     - Example:
       ```python
       def suggest_mitigations_with_atlas(vulnerability):
           # Logic to suggest mitigations using MITRE ATLAS
           return mitigation_suggestions
       ```

#### Best Practices for Using MITRE ATT&CK® and MITRE ATLAS

- **Keep Data Updated**:
  - Regularly fetch the latest data from MITRE ATT&CK® and MITRE ATLAS to ensure accuracy.

- **Use Structured Mapping**:
  - Use structured data formats (e.g., JSON) to map vulnerabilities to tactics, techniques, and mitigations.

- **Document Findings**:
  - Include detailed mappings and analyses in the final Markdown report generated by the system.

By integrating MITRE ATT&CK® and MITRE ATLAS into the Agent Purple project, both the Red Team and Blue Team agents can enhance their ability to identify, analyze, and mitigate vulnerabilities in AI-enabled systems.

---

### Utilizing the Official GitHub MCP Server

The Official GitHub MCP Server is a critical component of the Agent Purple project, enabling seamless interaction with GitHub repositories. Below are the guidelines for setting up and using the MCP server in this project.

#### Prerequisites

1. **Install Docker**: Ensure Docker is installed on your system. You can download it from [Docker's official website](https://www.docker.com/).
2. **Generate a GitHub Personal Access Token**:
   - Go to [GitHub Personal Access Tokens](https://github.com/settings/personal-access-tokens/new).
   - Generate a token with the necessary permissions (e.g., `repo`, `read:org`, `workflow`).
   - Store the token securely in the `.env` file:
     ```ini
     GITHUB_PERSONAL_ACCESS_TOKEN=your_github_personal_access_token
     ```

#### Setting Up the MCP Server

1. **Run the MCP Server Using Docker**:
   - Use the following command to start the MCP server:
     ```bash
     docker run -i --rm -e GITHUB_PERSONAL_ACCESS_TOKEN=your_github_personal_access_token ghcr.io/github/github-mcp-server
     ```
   - Replace `your_github_personal_access_token` with the token generated earlier.

2. **Configure MCP in VS Code (Optional)**:
   - Add the following configuration to your VS Code User Settings (JSON):
     ```json
     {
       "mcp": {
         "inputs": [
           {
             "type": "promptString",
             "id": "github_token",
             "description": "GitHub Personal Access Token",
             "password": true
           }
         ],
         "servers": {
           "github": {
             "command": "docker",
             "args": [
               "run",
               "-i",
               "--rm",
               "-e",
               "GITHUB_PERSONAL_ACCESS_TOKEN",
               "ghcr.io/github/github-mcp-server"
             ],
             "env": {
               "GITHUB_PERSONAL_ACCESS_TOKEN": "${input:github_token}"
             }
           }
         }
       }
     }
     ```

#### Using the MCP Server in Agent Purple

1. **Integration with `github_mcp_client.py`**:
   - The `utils/github_mcp_client.py` module interacts with the MCP server to clone repositories, list files, and fetch file contents.
   - Example usage:
     ```python
     from utils.github_mcp_client import GitHubMCPClient

     client = GitHubMCPClient()
     repo_url = "https://github.com/example/repo"
     client.clone_repository(repo_url)
     files = client.list_files()
     print(files)
     ```

2. **Available MCP Tools**:
   - The MCP server provides various tools for interacting with GitHub repositories, such as:
     - Cloning repositories
     - Fetching file contents
     - Managing issues and pull requests
   - Refer to the [GITHUB_MCP_README.md](./GITHUB_MCP_README.md) for a complete list of tools and their parameters.

3. **Error Handling**:
   - Ensure proper error handling when interacting with the MCP server. For example:
     ```python
     try:
         client.clone_repository(repo_url)
     except Exception as e:
         print(f"Error cloning repository: {e}")
     ```

4. **Testing MCP Integration**:
   - Write unit tests to validate the functionality of `github_mcp_client.py`.
   - Use mock responses to simulate MCP server interactions during testing.

#### Best Practices

- **Secure Token Management**: Always store the GitHub token in the `.env` file and never hardcode it in the codebase.
- **Monitor MCP Server Logs**: Check the server logs for any errors or warnings during execution.
- **Keep MCP Server Updated**: Regularly pull the latest Docker image to ensure compatibility and access to new features.

By following these guidelines, you can effectively utilize the GitHub MCP Server to enhance the functionality of the Agent Purple project.

---

### Motivation Analysis Agent

The Motivation Analysis Agent is responsible for analyzing vulnerabilities identified by the Red Team Agent to infer the developer's thought process or intent behind implementing potentially vulnerable code. This analysis helps provide context for the vulnerabilities, such as whether they were introduced due to oversight, performance optimization, lack of security awareness, or other reasons.

#### Key Objectives

- **Understand Developer Intent**: Analyze the code and associated metadata (e.g., comments, commit messages) to determine the possible motivations behind the implementation.
- **Provide Context**: Offer insights into why the vulnerability might have been introduced, aiding in root cause analysis and prioritization of fixes.

#### Integration with the Workflow

1. **Input**: The agent receives a list of vulnerabilities identified by the Red Team Agent.
2. **Processing**: It uses natural language processing (NLP) and contextual analysis to infer motivations based on code patterns, comments, and commit history.
3. **Output**: The agent produces a report detailing the inferred motivations for each vulnerability, which is then passed to the Blue Team Agent for remediation suggestions.

#### Example Use Case

- **Vulnerability**: Hardcoded credentials found in the code.
- **Inferred Motivation**: The developer might have hardcoded the credentials for quick testing or due to a lack of awareness about secure credential management practices.

By understanding the developer's intent, the system can provide more targeted and actionable recommendations for remediation.

---

### Step 4: Develop the Agent Modules

1. **Implement `agents/red_team_agent.py`:**  
   - Write the function that uses the OpenAI API to analyze code snippets for vulnerabilities and output results in JSON format.
   - Test with sample code snippets.

   **Commit Message:**  
   ```
   feat(agents): Implement red_team_agent for vulnerability scanning using OpenAI API
   ```

2. **Implement `agents/motivation_analysis_agent.py`:**  
   - Develop the module to analyze vulnerabilities and infer developer motivations.
   - Use sample JSON input from the red team and verify the output.

   **Commit Message:**  
   ```
   feat(agents): Implement motivation_analysis_agent to infer developer motivations
   ```

3. **Implement `agents/blue_team_agent.py`:**  
   - Code the function that suggests remediation fixes and outputs recommendations in JSON format.
   - Validate using sample vulnerabilities.

   **Commit Message:**  
   ```
   feat(agents): Add blue_team_agent to generate remediation recommendations
   ```

---

### Step 5: Implement Orchestration in `main.py` with AutoGen

1. **Set Up AutoGen Orchestration:**  
   - Integrate AutoGen to coordinate the agents. For example, wrap each agent function into an AutoGen `AssistantAgent` object and establish a conversation flow.
   - Example (simplified):
     ```python
     from autogen import AssistantAgent, Conversation

     red_team = AssistantAgent("RedTeam", function=red_team_agent_function)
     motivation_agent = AssistantAgent("MotivationAgent", function=motivation_analysis_agent_function)
     blue_team = AssistantAgent("BlueTeam", function=blue_team_agent_function)

     conversation = Conversation(agents=[red_team, motivation_agent, blue_team])
     conversation.start()
     ```
   - Ensure the orchestration coordinates agent execution and compiles a final report.

   **Commit Message:**  
   ```
   feat(main): Integrate AutoGen orchestration for multi-agent communication and report compilation
   ```

2. **Assemble the Report:**  
   - Use `GitHubMCPClient` to clone the repo, iterate over files, run agents, and compile a Markdown report.

   **Commit Message:**  
   ```
   feat(main): Add orchestration logic to iterate through repo files and compile security report
   ```

---

### Orchestrating with AutoGen

AutoGen is a framework developed by Microsoft for creating multi-agent AI applications that can act autonomously or work alongside humans. It provides a layered and extensible design, enabling developers to use it at different levels of abstraction. In the Agent Purple project, AutoGen is used to coordinate the interactions between the Red Team Agent, Motivation Analysis Agent, and Blue Team Agent. Below are the updated guidelines for integrating AutoGen into the project.

#### Key Features of AutoGen

1. **Layered Design**:
   - **Core API**: Implements message passing, event-driven agents, and local/distributed runtime for flexibility and power. It supports cross-language compatibility for .NET and Python.
   - **AgentChat API**: A simpler, opinionated API for rapid prototyping of common multi-agent patterns, such as two-agent or group chats.
   - **Extensions API**: Enables first- and third-party extensions, including specific implementations for LLM clients (e.g., OpenAI, AzureOpenAI) and capabilities like code execution.

2. **Developer Tools**:
   - **AutoGen Studio**: A no-code GUI for prototyping and running multi-agent workflows.
   - **AutoGen Bench**: A benchmarking suite for evaluating agent performance.

3. **Ecosystem**:
   - AutoGen supports a thriving community with regular updates, office hours, and a Discord server for collaboration and support.

#### Setting Up AutoGen

1. **Install AutoGen**:
   Add AutoGen to the `environment.yml` file:
   ```yaml
   - pip:
       - autogen-agentchat==0.5.1  # Replace with the latest version
       - autogen-ext[openai]==0.5.1
   ```
   Update the Conda environment:
   ```bash
   conda env update -f environment.yml
   ```

2. **Import AutoGen in Your Code**:
   - Example:
     ```python
     from autogen import AssistantAgent, Conversation
     ```

#### Using AutoGen for Orchestration

1. **Define Agent Functions**:
   - Each agent (Red Team, Motivation Analysis, Blue Team) should have a corresponding Python function that performs its task.
   - Example:
     ```python
     def red_team_agent_function(input_data):
         # Analyze code for vulnerabilities
         return vulnerabilities

     def motivation_analysis_agent_function(vulnerabilities):
         # Analyze developer motivations
         return motivations

     def blue_team_agent_function(motivations):
         # Suggest fixes for vulnerabilities
         return fixes
     ```

2. **Wrap Functions into AutoGen Agents**:
   - Use the `AssistantAgent` class to wrap each function.
   - Example:
     ```python
     red_team = AssistantAgent("RedTeam", function=red_team_agent_function)
     motivation_agent = AssistantAgent("MotivationAgent", function=motivation_analysis_agent_function)
     blue_team = AssistantAgent("BlueTeam", function=blue_team_agent_function)
     ```

3. **Create a Conversation**:
   - Use the `Conversation` class to define the flow of data between agents.
   - Example:
     ```python
     conversation = Conversation(agents=[red_team, motivation_agent, blue_team])
     conversation.start()
     ```

4. **Handle Input and Output**:
   - Pass the initial input (e.g., repository data) to the first agent and collect the final output from the last agent.
   - Example:
     ```python
     repository_data = {"repo_url": "https://github.com/example/repo"}
     conversation.start(input_data=repository_data)
     final_report = conversation.get_output()
     ```

#### Best Practices for Using AutoGen

- **Modular Design**: Keep each agent’s function focused on a single responsibility.
- **Error Handling**: Implement error handling within each agent function to ensure smooth execution.
- **Logging**: Use logging to track the flow of data and debug issues.
- **Testing**: Test each agent function independently before integrating them into the AutoGen conversation.
- **Leverage Developer Tools**: Use AutoGen Studio for prototyping workflows and AutoGen Bench for performance evaluation.

By leveraging AutoGen, you can simplify the orchestration of the multi-agent system in the Agent Purple project, ensuring a seamless flow of data and efficient collaboration between agents.

---

### Step 6: Create the Frontend with Gradio

1. **Implement `frontend/app.py`:**  
   - Create a Gradio interface to enter a repo URL and return the generated Markdown report using the orchestration backend.

   **Commit Message:**  
   ```
   feat(frontend): Implement Gradio-based UI for repository assessment and report display
   ```

2. **Test the Interface:**  
   - Ensure successful launch and functionality.

---

### Step 7: Integration Testing and Refinement

1. **Test End-to-End Flow:**  
   - Validate complete flow via CLI and frontend.

   **Commit Message:**  
   ```
   fix: Resolve integration issues between agents and improve error handling during repo analysis
   ```

2. **Documentation and Cleanup:**  
   - Refactor code, update README, and comment functions for clarity.

   **Commit Message:**  
   ```
   docs: Update README and add inline documentation for clarity
   ```

3. **(Optional) Add Unit Tests:**  
   - Add tests for utility functions or JSON structure.

   **Commit Message:**  
   ```
   test: Add basic unit tests for utility modules and agent functions
   ```

---

### Step 8: Deployment

1. **Local Deployment:**  
   - Run the Gradio app locally using:
     ```bash
     python frontend/app.py
     ```

2. **Cloud Deployment:**  
   - Use platforms like AWS, Azure, or Heroku for deployment.
   - Ensure all environment variables are securely configured.

   **Commit Message:**  
   ```
   chore: Add deployment instructions for local and cloud environments
   ```

---

### Step 9: Final Submission Preparation

1. **Final Cleanup:**  
   - Remove debug code and ensure submission readiness.

   **Commit Message:**  
   ```
   chore: Final code cleanup and project review before submission
   ```

2. **Push and Tag Final Release:**  
   ```bash
   git tag v1.0
   git push origin v1.0
   ```

   **Commit Message:**  
   ```
   feat: Tag final stable release version for hackathon submission
   ```

---

### Leveraging DSPy for Modular AI System Development

DSPy (Declarative Self-improving Python) is a framework designed for programming language models (LMs) rather than relying on brittle prompt engineering. It enables developers to build modular AI systems, optimize their prompts and weights, and iterate quickly on AI behavior. Below are the guidelines for integrating DSPy into the Agent Purple project.

#### Use Cases for DSPy in Agent Purple

1. **Modular Agent Design**:
   - Use DSPy to define modular AI components for each agent (Red Team, Motivation Analysis, Blue Team).
   - Example: Create a DSPy module for the Red Team Agent to analyze code snippets and return structured vulnerability data.

2. **Optimization of Agent Behavior**:
   - Use DSPy’s optimizers to improve the performance of each agent by refining their prompts and weights.
   - Example: Optimize the Motivation Analysis Agent to better infer developer intent by synthesizing high-quality few-shot examples.

3. **Compositional AI Systems**:
   - Combine multiple DSPy modules to create a compositional AI system that integrates all agents seamlessly.
   - Example: Use DSPy’s `ChainOfThought` or `ReAct` modules to coordinate the flow of data between agents.

4. **Iterative Improvement**:
   - Continuously improve the system by re-compiling DSPy modules with updated metrics or task requirements.

#### Setting Up DSPy

1. **Install DSPy**:
   Add DSPy to the `environment.yml` file:
   ```yaml
   - pip:
       - dspy==1.0.0  # Replace with the latest version
   ```
   Update the Conda environment:
   ```bash
   conda env update -f environment.yml
   ```

2. **Import DSPy in Your Code**:
   - Example:
     ```python
     import dspy

     # Configure the language model
     lm = dspy.LM('openai/gpt-4o-mini', api_key='YOUR_OPENAI_API_KEY')
     dspy.configure(lm=lm)
     ```

#### Integrating DSPy into Agent Purple

1. **Define Agent Modules**:
   - Use DSPy to define modules for each agent.
   - Example:
     ```python
     from dspy import Predict

     red_team_module = Predict("code_snippet -> vulnerabilities: list")
     motivation_module = Predict("vulnerabilities -> motivations: list")
     blue_team_module = Predict("motivations -> fixes: list")
     ```

2. **Optimize Agent Behavior**:
   - Use DSPy’s optimizers to refine the behavior of each module.
   - Example:
     ```python
     from dspy import MIPROv2

     optimizer = MIPROv2(metric=dspy.evaluate.answer_exact_match)
     optimized_red_team = optimizer.compile(red_team_module, trainset=train_data)
     ```

3. **Compose Modules**:
   - Combine DSPy modules to create a pipeline for the entire system.
   - Example:
     ```python
     from dspy import ChainOfThought

     pipeline = ChainOfThought([
         red_team_module,
         motivation_module,
         blue_team_module
     ])

     result = pipeline.run(input_data)
     ```

4. **Iterate and Improve**:
   - Re-compile modules with updated metrics or representative inputs to improve system performance over time.

#### Best Practices for Using DSPy

- **Modular Design**: Define each agent as a separate DSPy module for better maintainability and reusability.
- **Optimization**: Use DSPy’s optimizers to refine prompts and weights for each module.
- **Documentation**: Document the input/output behavior of each module for clarity.
- **Testing**: Validate each module independently before integrating them into the system.

By leveraging DSPy, the Agent Purple project can benefit from a modular and optimizable AI system, enabling faster iteration and higher-quality outputs.

---

## Additional Best Practices

- **Version Control:**  
  Commit often, write clear messages.

- **Modularity & Testing:**  
  Follow single-responsibility principle and test agents independently.

- **Secure API Handling:**  
  Use `.env`, `python-dotenv`, and NEVER commit sensitive keys.

- **Orchestration with AutoGen:**  
  Use `AssistantAgent` + `Conversation` classes. Stream results between agents and compile output in main script.

- **Documentation:**  
  Keep `README.md` and this guide up to date.

- **Code Quality:**  
  Use type hints, docstrings, and tools like `flake8` and `black` for linting and formatting.

---

*End of DEVELOPMENT_GUIDE.md*