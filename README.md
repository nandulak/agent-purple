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
- **Red Team Agent:** Scans code for vulnerabilities using OpenAI API.
- **Motivation Analysis Agent:** Analyzes developer motivations behind vulnerabilities.
- **Blue Team Agent:** Suggests fixes for identified issues.
- **Orchestration:** Coordinates agents using AutoGen.
- **Frontend:** Gradio-based interface for user interaction.
- **Data Fetcher:** Retrieves and processes MITRE ATT&CK and ATLAS data with intelligent caching.

## Core Components

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
├── frontend/                 # Gradio-based frontend
├── utils/                    # Utility modules
│   ├── data_fetcher.py       # MITRE data retrieval and processing
│   └── github_mcp_client.py  # GitHub repository interaction
├── .env                      # API keys and tokens
├── environment.yml           # Conda environment definition
├── main.py                   # Orchestration script
└── README.md                 # Project overview and setup instructions
```

## Contributing
Contributions are welcome! Please fork the repository and submit a pull request.

## License
This project is licensed under the MIT License. See the LICENSE file for details.
