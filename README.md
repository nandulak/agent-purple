# Agent Purple: AI Vulnerability Assessor

Agent Purple is a multi-agent system designed to autonomously scan GitHub repositories for vulnerabilities in AI-enabled systems. It leverages OpenAI's API, MITRE ATT&CK/ATLAS frameworks, and GitHub MCP Server to identify, analyze, and remediate potential security issues.

## Purpose
Agent Purple aims to:
- Identify vulnerabilities in AI-enabled systems.
- Infer developer motivations behind code issues.
- Suggest code-level and conceptual fixes.
- Provide a user-friendly interface for security assessments.

## Setup Instructions

### 1. Clone the Repository
```bash
# Clone the repository
$ git clone https://github.com/your-username/agent-purple.git
$ cd agent-purple
```

### 2. Set Up Conda Environment
```bash
# Create and activate the Conda environment
$ conda env create -f environment.yml
$ conda activate agent_purple
```

### 3. Configure API Keys
1. Create a `.env` file in the project root directory.
2. Add your API keys and personal access tokens:
   ```ini
   OPENAI_API_KEY=your_openai_api_key
   GITHUB_PERSONAL_ACCESS_TOKEN=your_github_personal_access_token
   ```

### 4. Run the Application
```bash
# Launch the Gradio frontend
$ python frontend/app.py
```

## Features
- **Red Team Agent:** Scans code for vulnerabilities using OpenAI's GPT-4o API, including AI-specific vulnerabilities detection and mapping to MITRE ATT&CK and ATLAS frameworks.
- **Motivation Analysis Agent:** Analyzes developer motivations behind vulnerabilities.
- **Blue Team Agent:** Suggests fixes for identified issues.
- **Orchestration:** Coordinates agents using AutoGen.
- **Frontend:** Gradio-based interface for user interaction.
- **Data Fetcher:** Retrieves and processes MITRE ATT&CK and ATLAS data with intelligent caching.

## Core Components

### Red Team Agent
The `agents/red_team_agent.py` module provides comprehensive code vulnerability scanning using OpenAI's GPT-4o model:

- Identifies common security vulnerabilities in code repositories
- Detects AI-specific vulnerabilities in machine learning codebases
- Maps vulnerabilities to MITRE ATT&CK and ATLAS frameworks
- Provides severity ratings and detailed explanations of vulnerabilities
- Implements result caching to minimize redundant API calls

To run tests for the Red Team Agent:
```bash
# Run the Red Team Agent tests
$ python -m pytest tests/test_red_team_agent.py tests/test_red_team_ai_vulnerabilities.py
```

To run an integration test with a real AI repository:
```bash
# Run the integration test with a real AI codebase
$ python tests/test_red_team_integration.py
```

### Motivation Analysis Agent
The `agents/motivation_analysis_agent.py` module analyzes vulnerabilities identified by the Red Team Agent to infer possible developer motivations:

- Uses GPT-4o to perform psychological analysis of developer motivations behind vulnerabilities
- Categorizes motivations (e.g., convenience, knowledge gap, deadline pressure)
- Identifies patterns across multiple vulnerabilities in a repository
- Generates organizational recommendations to address root causes
- Implements caching to optimize performance and reduce API costs

To run tests for the Motivation Analysis Agent:
```bash
# Run unit tests
$ python -m pytest tests/test_motivation_analysis_agent.py

# Run integration tests with the Red Team Agent
$ python -c "import os; os.environ['RUN_INTEGRATION_TESTS'] = '1'; import pytest; pytest.main(['-v', 'tests/test_motivation_analysis_agent.py::test_integration_with_red_team_agent', 'tests/test_motivation_analysis_agent.py::test_end_to_end_analysis_flow'])"
```

### Blue Team Agent
The `agents/blue_team_agent.py` module provides comprehensive remediation strategies for vulnerabilities identified by the Red Team Agent:

- Generates code-level fixes with detailed explanations for identified vulnerabilities
- Takes into account developer motivations from the Motivation Analysis Agent to provide targeted solutions
- Suggests conceptual recommendations to prevent similar vulnerabilities in the future
- Provides organizational improvements for long-term security enhancement
- Creates a prioritized list of actions to address vulnerabilities based on severity and impact
- Recommends security frameworks, training resources, and monitoring tools
- Includes links to security standards and best practices resources

To run tests for the Blue Team Agent:
```bash
# Run unit tests
$ python -m pytest tests/test_blue_team_agent.py

# Run integration tests with the Red Team Agent and Motivation Analysis Agent
$ python -m pytest tests/test_blue_team_integration.py
```

### Data Fetcher
The `utils/data_fetcher.py` module provides comprehensive functionality for retrieving, parsing, and utilizing threat intelligence data:

- Retrieves MITRE ATT&CK data for enterprise, mobile, and ICS domains
- Fetches MITRE ATLAS data specifically for AI system vulnerabilities
- Implements local caching to minimize API calls and enable offline use
- Maps vulnerabilities to specific tactics and techniques from both frameworks
- Provides robust error handling and graceful degradation when resources are unavailable

To test the data fetcher functionality:
```bash
# Run the data fetcher test
$ python -m utils.data_fetcher
```

## Project Structure
```
agent_purple/
├── data/                      # Stores MITRE ATT&CK/ATLAS data
│   ├── mitre_attack/         # Local cache for ATT&CK data
│   └── mitre_atlas/          # Local cache for ATLAS data
├── agents/                   # Agent modules
│   ├── red_team_agent.py     # Vulnerability scanning with GPT-4o
│   ├── motivation_analysis_agent.py  # Developer motivation inference
│   └── blue_team_agent.py    # Remediation recommendation
├── frontend/                 # Gradio-based frontend
├── utils/                    # Utility modules
│   ├── data_fetcher.py       # MITRE data retrieval and processing
│   └── github_client.py      # GitHub repository interaction
├── tests/                    # Test suite
│   ├── test_red_team_agent.py              # General vulnerability tests
│   ├── test_red_team_ai_vulnerabilities.py # AI-specific vulnerability tests
│   ├── test_red_team_integration.py        # Real-world AI repo testing
│   ├── test_motivation_analysis_agent.py   # Developer motivation analysis tests
│   └── test_blue_team_agent.py             # Remediation recommendation tests
├── test_results/             # Test output and reports
├── .env                      # API keys and tokens
├── environment.yml           # Conda environment definition
├── main.py                   # Orchestration script
└── README.md                 # Project overview and setup instructions
```

## Contributing
Contributions are welcome! Please fork the repository and submit a pull request.

## License
This project is licensed under the MIT License. See the LICENSE file for details.
