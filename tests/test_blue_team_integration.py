"""
Integration tests for the Blue Team Agent.

This module contains integration tests that verify the Blue Team Agent works correctly
with other components of the system, including the Red Team Agent and Motivation
Analysis Agent in a full workflow.
"""

import os
import json
import pytest
import time
import tempfile
import shutil
from pathlib import Path

# Import agent modules
from agents.red_team_agent import analyze_file, analyze_repository
from agents.motivation_analysis_agent import motivation_analysis_agent_function
from agents.blue_team_agent import blue_team_agent_function
from utils.github_client import GitHubClient

# Skip markers for optional tests
skip_if_no_api_key = pytest.mark.skipif(
    os.environ.get("OPENAI_API_KEY") is None,
    reason="OpenAI API key not set in environment variables",
)

skip_if_no_integration = pytest.mark.skipif(
    os.environ.get("RUN_INTEGRATION_TESTS") != "1",
    reason="Integration tests are disabled. Set RUN_INTEGRATION_TESTS=1 to enable.",
)


@pytest.fixture
def vulnerable_code_file():
    """Create a temporary file with vulnerable code for testing."""
    # Create a temporary directory
    temp_dir = tempfile.mkdtemp()
    file_path = os.path.join(temp_dir, "vulnerable_code.py")

    # Write vulnerable code to the file
    with open(file_path, "w") as f:
        f.write(
            """
# Example AI system with vulnerabilities
import pickle
import numpy as np
import requests
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier

class VulnerableAISystem:
    def __init__(self):
        self.model = None
        self.api_key = "sk_test_AbCdEfGhIjKlMnOpQrStUvWxYz123456"  # Hardcoded API key
    
    def load_model(self, model_path):
        # Vulnerability: Insecure deserialization
        with open(model_path, 'rb') as f:
            self.model = pickle.load(f)
    
    def train_model(self, data, labels):
        # Split data into train and test sets
        X_train, X_test, y_train, y_test = train_test_split(data, labels, test_size=0.2)
        
        # Train a random forest model
        model = RandomForestClassifier()
        model.fit(X_train, y_train)
        
        self.model = model
        return model
    
    def predict(self, user_input):
        # Vulnerability: No input validation
        # Directly using user input without validation
        return self.model.predict(user_input)
    
    def fetch_external_data(self, user_url):
        # Vulnerability: SSRF vulnerability
        # Direct use of user-supplied URL without validation
        response = requests.get(user_url)
        return response.json()
    
    def log_prediction(self, user_id, input_data, prediction):
        # Vulnerability: SQL Injection
        query = f"INSERT INTO predictions (user_id, prediction) VALUES ('{user_id}', '{prediction}')"
        # Execute the vulnerable query (simulated)
        return query
        """
        )

    yield file_path

    # Cleanup
    shutil.rmtree(temp_dir)


@skip_if_no_api_key
@skip_if_no_integration
def test_blue_team_integration_with_real_agents(vulnerable_code_file):
    """
    Test the integration of Blue Team Agent with Red Team and Motivation Analysis agents
    on an actual vulnerable file.

    This test:
    1. Uses the Red Team Agent to identify vulnerabilities in a file
    2. Passes those vulnerabilities to the Motivation Analysis Agent
    3. Passes both results to the Blue Team Agent for remediation recommendations
    """
    # Step 1: Analyze the file with Red Team Agent
    print("\nRunning Red Team Agent analysis...")

    # Read file content
    with open(vulnerable_code_file, "r") as f:
        file_content = f.read()

    red_team_results = analyze_file(vulnerable_code_file, file_content)

    # Verify Red Team found vulnerabilities
    assert "vulnerabilities" in red_team_results
    assert len(red_team_results["vulnerabilities"]) > 0
    print(
        f"Red Team Agent identified {len(red_team_results['vulnerabilities'])} vulnerabilities"
    )

    # Step 2: Analyze vulnerabilities with Motivation Analysis Agent
    print("\nRunning Motivation Analysis...")
    motivation_results = motivation_analysis_agent_function(red_team_results)

    # Verify Motivation Analysis worked correctly
    assert "individual_analyses" in motivation_results
    assert len(motivation_results["individual_analyses"]) > 0
    print(
        f"Motivation Analysis Agent analyzed {len(motivation_results['individual_analyses'])} vulnerabilities"
    )

    # Step 3: Generate fixes with Blue Team Agent
    print("\nRunning Blue Team Agent analysis...")
    blue_team_results = blue_team_agent_function(red_team_results, motivation_results)

    # Verify Blue Team generated remediation recommendations
    assert "vulnerabilities_remediated" in blue_team_results
    assert "individual_remediations" in blue_team_results
    assert "overall_recommendations" in blue_team_results
    assert blue_team_results["vulnerabilities_remediated"] > 0
    print(
        f"Blue Team Agent provided remediation for {blue_team_results['vulnerabilities_remediated']} vulnerabilities"
    )

    # Save the integration test results
    results_dir = Path("test_results")
    results_dir.mkdir(exist_ok=True)

    with open(results_dir / "blue_team_integration_test_results.json", "w") as f:
        json.dump(blue_team_results, f, indent=2)

    print(f"Results saved to {results_dir / 'blue_team_integration_test_results.json'}")


@skip_if_no_api_key
@skip_if_no_integration
def test_end_to_end_analysis_workflow():
    """
    Test the complete end-to-end workflow of using all three agents together
    to analyze a small repository and generate a comprehensive security report.
    """
    # This test simulates analyzing a repository by creating a temp directory
    # with vulnerable code files and running all three agents on it

    # Create temporary directory to simulate a repository
    repo_dir = tempfile.mkdtemp()
    try:
        # Create multiple vulnerable files
        files = [
            (
                "vulnerable_ai.py",
                """
import pickle
import numpy as np
from sklearn.ensemble import RandomForestClassifier

class UnsafeAIModel:
    def load_model(self, path):
        # Vulnerability: Insecure deserialization
        with open(path, 'rb') as f:
            return pickle.load(f)
    
    def train(self, data, labels):
        model = RandomForestClassifier()
        model.fit(data, labels)
        return model
            """,
            ),
            (
                "api_service.py",
                """
import requests

def fetch_user_data(user_url):
    # Vulnerability: SSRF
    return requests.get(user_url).json()

def process_model_input(user_input):
    # Vulnerability: No input validation
    processed = user_input * 2 
    return processed
            """,
            ),
        ]

        # Write files to temporary directory
        file_paths = []
        for filename, content in files:
            file_path = os.path.join(repo_dir, filename)
            with open(file_path, "w") as f:
                f.write(content)
            file_paths.append(file_path)

        # Create mock repository info
        repo_info = {
            "repository_info": {
                "name": "test-ai-repo",
                "owner": "test-user",
                "url": "https://github.com/test-user/test-ai-repo",
            }
        }

        print("\nRunning end-to-end analysis workflow...")

        # Step 1: Run Red Team Agent on all files
        all_vulnerabilities = []
        for file_path in file_paths:
            # Read file content
            with open(file_path, "r") as f:
                file_content = f.read()

            file_results = analyze_file(file_path, file_content)
            if "vulnerabilities" in file_results and file_results["vulnerabilities"]:
                all_vulnerabilities.extend(file_results["vulnerabilities"])

        # Combine results into repository-level results
        red_team_results = {
            "vulnerabilities": all_vulnerabilities,
            "vulnerability_count": len(all_vulnerabilities),
            "analysis_timestamp": time.time(),
            "total_files_analyzed": len(file_paths),
            **repo_info,
        }

        assert red_team_results["vulnerability_count"] > 0
        print(
            f"Red Team identified {red_team_results['vulnerability_count']} vulnerabilities across {len(file_paths)} files"
        )

        # Step 2: Run Motivation Analysis Agent
        motivation_results = motivation_analysis_agent_function(red_team_results)

        assert "individual_analyses" in motivation_results
        assert len(motivation_results["individual_analyses"]) > 0
        print(
            f"Motivation Analysis Agent analyzed {len(motivation_results['individual_analyses'])} vulnerabilities"
        )

        # Step 3: Run Blue Team Agent
        blue_team_results = blue_team_agent_function(
            red_team_results, motivation_results
        )

        assert "vulnerabilities_remediated" in blue_team_results
        assert "individual_remediations" in blue_team_results
        assert "overall_recommendations" in blue_team_results
        print(
            f"Blue Team Agent provided remediation for {blue_team_results['vulnerabilities_remediated']} vulnerabilities"
        )

        # Save the integration test results
        results_dir = Path("test_results")
        results_dir.mkdir(exist_ok=True)

        with open(results_dir / "end_to_end_analysis_test_results.json", "w") as f:
            json.dump(
                {
                    "red_team_results": red_team_results,
                    "motivation_analysis_results": motivation_results,
                    "blue_team_results": blue_team_results,
                },
                f,
                indent=2,
            )

        print(
            f"End-to-end results saved to {results_dir / 'end_to_end_analysis_test_results.json'}"
        )

    finally:
        # Clean up
        shutil.rmtree(repo_dir)


if __name__ == "__main__":
    pytest.main(["-xvs", __file__])
