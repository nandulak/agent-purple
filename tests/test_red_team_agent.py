"""
Tests for the Red Team Agent functionality.

This module contains tests for verifying that the Red Team Agent correctly identifies
vulnerabilities in code and properly maps them to MITRE frameworks.
"""

import os
import json
import pytest
from unittest.mock import patch, MagicMock
import tempfile

# Import the Red Team Agent module
from agents.red_team_agent import (
    analyze_code_with_openai,
    map_vulnerability_to_frameworks,
    analyze_file,
    analyze_repository,
    should_analyze_file,
    cache_api_call,
)


@pytest.fixture
def sample_code_with_vulnerabilities():
    """Fixture that provides a code sample with known vulnerabilities."""
    return """
    def process_user_input(user_input):
        # This function processes user input for an AI model
        sql_query = "SELECT * FROM users WHERE username = '" + user_input + "'"
        return execute_query(sql_query)

    def train_model(data_path):
        # Load training data without validation
        training_data = load_data(data_path)
        
        # Initialize model with default parameters
        model = AIModel()
        
        # Train the model
        api_key = "sk_test_AbCdEfGhIjKlMnOpQrStUvWxYz123456"
        model.train(training_data, api_key=api_key)
        
        return model
    """


@pytest.fixture
def mock_openai_response():
    """Mock response from the OpenAI API for vulnerability analysis."""
    return {
        "vulnerabilities": [
            {
                "description": "SQL Injection vulnerability due to direct concatenation of user input",
                "severity": "CRITICAL",
                "line_numbers": [3],
                "vulnerability_type": "SQL Injection",
                "exploitation_scenarios": "An attacker could input malicious SQL to access unauthorized data",
                "ai_impact": "Could compromise the AI system's training data or expose sensitive information",
            },
            {
                "description": "Hardcoded API key in source code",
                "severity": "HIGH",
                "line_numbers": [14],
                "vulnerability_type": "Credentials Management",
                "exploitation_scenarios": "API key could be extracted from source code and misused",
                "ai_impact": "Could allow unauthorized access to AI services or models",
            },
        ]
    }


@pytest.fixture
def mock_framework_mapping():
    """Mock response for framework mapping."""
    return {
        "mitre_attack": {
            "tactics": [{"id": "TA0001", "name": "Initial Access"}],
            "techniques": [
                {"id": "T1190", "name": "Exploit Public-Facing Application"}
            ],
            "explanation": "This vulnerability allows exploitation of the application's interface",
        },
        "mitre_atlas": {
            "tactics": [{"id": "TA0043", "name": "ML Model Access"}],
            "techniques": [{"id": "AML.T0009", "name": "API Exploitation"}],
            "explanation": "This vulnerability could enable unauthorized access to ML APIs",
        },
    }


def test_should_analyze_file():
    """Test the file filtering functionality."""
    # Files that should be analyzed
    assert should_analyze_file("src/main.py") == True
    assert should_analyze_file("models/neural_network.py") == True
    assert should_analyze_file("app.js") == True

    # Files that should be skipped
    assert should_analyze_file("image.jpg") == False
    assert should_analyze_file("node_modules/package.json") == False
    assert should_analyze_file("__pycache__/module.pyc") == False
    assert should_analyze_file(".git/HEAD") == False


@patch("agents.red_team_agent.client.chat.completions.create")
def test_analyze_code_with_openai(mock_openai_api, mock_openai_response):
    """Test the OpenAI API integration for code analysis."""
    # Setup the mock response
    mock_completion = MagicMock()
    mock_completion.choices[0].message.content = json.dumps(mock_openai_response)
    mock_openai_api.return_value = mock_completion

    # Test the function
    result = analyze_code_with_openai("def vulnerable_function(): pass", "test_file.py")

    # Verify the result
    assert "vulnerabilities" in result
    assert len(result["vulnerabilities"]) == 2
    assert result["vulnerabilities"][0]["severity"] == "CRITICAL"
    assert result["vulnerabilities"][1]["severity"] == "HIGH"

    # Verify that the API was called with the right parameters
    mock_openai_api.assert_called_once()
    args, kwargs = mock_openai_api.call_args
    assert kwargs["model"] == "gpt-4o"  # Updated to expect gpt-4o instead of gpt-4
    assert len(kwargs["messages"]) == 2
    assert "test_file.py" in kwargs["messages"][1]["content"]


@patch("agents.red_team_agent.client.chat.completions.create")
def test_map_vulnerability_to_frameworks(mock_openai_api, mock_framework_mapping):
    """Test the mapping of vulnerabilities to MITRE frameworks."""
    # Setup the mock response
    mock_completion = MagicMock()
    mock_completion.choices[0].message.content = json.dumps(mock_framework_mapping)
    mock_openai_api.return_value = mock_completion

    # Create a sample vulnerability
    vulnerability = {
        "description": "SQL Injection vulnerability",
        "vulnerability_type": "SQL Injection",
        "ai_impact": "Data compromise",
    }

    # Test the function
    result = map_vulnerability_to_frameworks(vulnerability)

    # Verify framework mappings were added to the vulnerability
    assert "framework_mappings" in result
    assert "mitre_attack" in result["framework_mappings"]
    assert "mitre_atlas" in result["framework_mappings"]

    # Verify specific mapping details
    attack = result["framework_mappings"]["mitre_attack"]
    assert attack["tactics"][0]["id"] == "TA0001"
    assert attack["techniques"][0]["id"] == "T1190"

    atlas = result["framework_mappings"]["mitre_atlas"]
    assert atlas["tactics"][0]["id"] == "TA0043"
    assert atlas["techniques"][0]["id"] == "AML.T0009"


@patch("agents.red_team_agent.analyze_code_with_openai")
@patch("agents.red_team_agent.map_vulnerability_to_frameworks")
def test_analyze_file(
    mock_map_frameworks, mock_analyze_code, mock_openai_response, mock_framework_mapping
):
    """Test the file analysis functionality."""
    # Setup mocks
    mock_analyze_code.return_value = mock_openai_response

    # Mock the mapping function to return the vulnerability with mappings added
    def side_effect(vuln):
        vuln["framework_mappings"] = mock_framework_mapping
        return vuln

    mock_map_frameworks.side_effect = side_effect

    # Test the function
    result = analyze_file("test_file.py", "def vulnerable_function(): pass")

    # Verify the result structure
    assert "file_path" in result
    assert "vulnerabilities" in result
    assert "vulnerability_count" in result
    assert "analysis_timestamp" in result
    assert "analysis_duration_seconds" in result

    # Verify content
    assert result["file_path"] == "test_file.py"
    assert result["vulnerability_count"] == 2
    assert len(result["vulnerabilities"]) == 2

    # Verify that vulnerabilities have framework mappings
    assert "framework_mappings" in result["vulnerabilities"][0]
    assert "mitre_attack" in result["vulnerabilities"][0]["framework_mappings"]
    assert "mitre_atlas" in result["vulnerabilities"][0]["framework_mappings"]


@patch("agents.red_team_agent.analyze_file")
def test_analyze_repository(mock_analyze_file, mock_openai_response):
    """Test the repository analysis functionality."""

    # Setup mock for analyze_file to return results with vulnerabilities
    def mock_analyze_file_impl(file_path, file_content):
        return {
            "file_path": file_path,
            "analysis_timestamp": 1619712000,
            "analysis_duration_seconds": 0.5,
            "vulnerabilities": mock_openai_response["vulnerabilities"],
            "vulnerability_count": len(mock_openai_response["vulnerabilities"]),
            "error": None,
        }

    mock_analyze_file.side_effect = mock_analyze_file_impl

    # Create test repository files
    repository_files = [
        {"file_path": "src/app.py", "content": "def app(): pass"},
        {"file_path": "src/models.py", "content": "def model(): pass"},
        {"file_path": "tests/test_app.py", "content": "def test(): pass"},
        {"file_path": "README.md", "content": "# Project"},
    ]

    # Test the function
    result = analyze_repository(repository_files)

    # Verify result structure
    assert "total_files_analyzed" in result
    assert "total_vulnerabilities" in result
    assert "vulnerability_summary" in result
    assert "vulnerabilities" in result
    assert "file_results" in result

    # Verify content
    assert result["total_files_analyzed"] == 4
    assert result["total_vulnerabilities"] == 8  # 2 vulnerabilities × 4 files

    # Verify the vulnerability summary
    assert (
        result["vulnerability_summary"]["CRITICAL"] == 4
    )  # 1 critical per file × 4 files
    assert result["vulnerability_summary"]["HIGH"] == 4  # 1 high per file × 4 files


def test_cache_api_call():
    """Test that the caching decorator works correctly."""

    # Define a simple function to cache
    @cache_api_call
    def expensive_function(arg1, arg2):
        # This simulates an expensive operation that should be cached
        return f"{arg1}_{arg2}"

    # First call should execute the function
    result1 = expensive_function("test", 123)
    assert result1 == "test_123"

    # Second call with same args should use cache
    result2 = expensive_function("test", 123)
    assert result2 == "test_123"
    assert result1 == result2  # Results should be identical

    # Call with different args should execute the function again
    result3 = expensive_function("different", 456)
    assert result3 == "different_456"
    assert result3 != result1  # Results should be different


@pytest.mark.integration
def test_end_to_end_with_real_code(sample_code_with_vulnerabilities):
    """
    Integration test for analyzing real code.
    This test is marked as an integration test and requires API keys to run.
    """
    # Only run if API key is available and integration tests are enabled
    if not os.getenv("OPENAI_API_KEY") or not os.getenv("RUN_INTEGRATION_TESTS"):
        pytest.skip("Skipping integration test - API key or flag not set")

    # Create a temporary file with the sample code
    with tempfile.NamedTemporaryFile(suffix=".py", delete=False) as temp_file:
        temp_file.write(sample_code_with_vulnerabilities.encode())
        temp_path = temp_file.name

    try:
        # Test a full file analysis with real API calls
        result = analyze_file(temp_path, sample_code_with_vulnerabilities)

        # Basic validation of the result structure
        assert "vulnerabilities" in result
        assert isinstance(result["vulnerabilities"], list)
        assert "analysis_duration_seconds" in result

        # If vulnerabilities were found, check their structure
        if result["vulnerabilities"]:
            vuln = result["vulnerabilities"][0]
            assert "description" in vuln
            assert "severity" in vuln
            assert "framework_mappings" in vuln
    finally:
        # Clean up the temporary file
        os.unlink(temp_path)


if __name__ == "__main__":
    pytest.main(["-xvs", __file__])
