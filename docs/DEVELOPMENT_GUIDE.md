
# Agent Purple – Development Guide

This document provides the necessary context, architecture details, and a step-by-step guide for implementing the multi-agent system that scans GitHub repositories for vulnerabilities in AI-enabled systems. It is designed to guide GitHub Copilot Agent mode (and you) through developing each module, integrating them, and committing the work incrementally using best practices.

> **Project Overview:**  
> The system comprises multiple agents that work together autonomously:
> - **Red Team Agent:** Scans code (using the OpenAI API) for vulnerabilities and maps them to MITRE ATT&CK/ATLAS reference IDs.
> - **Motivation Analysis Agent:** Analyzes each vulnerability to infer possible developer motivations behind the code issues.
> - **Blue Team Agent:** Suggests code-level and conceptual fixes for the identified vulnerabilities.
> - **Orchestration:** Uses AutoGen to coordinate the agents.
> - **Frontend:** A Gradio web interface presents the final Markdown report.
> - **Repository Integration:** The Official GitHub MCP server is used to clone and analyze target repositories.
>
> **Key Principles:**  
> - Use modular, self-contained Python modules.
> - Adhere to best practices and standards (PEP8, SOLID principles, clear error handling).
> - Test each module individually.
> - Commit incremental progress with clear, descriptive messages.
> - Store secrets (API keys) securely and do not commit them to version control.

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
   You can install dependencies using pip. Create an `environment.yml` file (see below) for reproducibility:

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
   Create/Edit the `.gitignore` file in your project’s root directory with content similar to:
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

### Step 2: Establish Project Structure

1. **Create Directory Layout and Placeholder Files:**  
   - Create folders: `data/`, `agents/`, `frontend/`, `utils/`.
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

### Step 8: Final Submission Preparation

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

---

*End of DEVELOPMENT_GUIDE.md*