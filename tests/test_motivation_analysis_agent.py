"""
Tests for the Motivation Analysis Agent functionality.

This module contains tests for verifying that the Motivation Analysis Agent correctly
analyzes vulnerabilities, infers developer motivations, and identifies patterns
across multiple vulnerabilities.
"""

import os
import json
import pytest
import time
from unittest.mock import patch, MagicMock
import tempfile
from pathlib import Path
from datetime import datetime

# Import the Motivation Analysis Agent module
from agents.motivation_analysis_agent import (
    analyze_vulnerability_motivation,
    analyze_vulnerability_set,
    analyze_motivation_patterns,
    analyze_repository_results,
    motivation_analysis_agent_function,
    cache_api_call,
)

# Import Red Team Agent for integration testing
from agents.red_team_agent import analyze_code_with_openai, analyze_file


@pytest.fixture
def sample_vulnerability():
    """Fixture that provides a sample vulnerability for testing."""
    return {
        "description": "SQL Injection vulnerability due to direct concatenation of user input",
        "severity": "CRITICAL",
        "line_numbers": [3],
        "vulnerability_type": "SQL Injection",
        "exploitation_scenarios": "An attacker could input malicious SQL to access unauthorized data",
        "ai_impact": "Could compromise the AI system's training data or expose sensitive information",
        "code_context": """
def process_user_input(user_input):
    # This function processes user input for an AI model
    sql_query = "SELECT * FROM users WHERE username = '" + user_input + "'"
    return execute_query(sql_query)
        """,
    }


@pytest.fixture
def sample_vulnerability_set():
    """Fixture that provides a set of sample vulnerabilities for testing."""
    return [
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
        {
            "description": "Insecure deserialization using pickle",
            "severity": "CRITICAL",
            "line_numbers": [22, 23],
            "vulnerability_type": "Insecure Deserialization",
            "exploitation_scenarios": "An attacker could craft a malicious object to achieve remote code execution",
            "ai_impact": "Could compromise the entire AI system and host environment",
        },
    ]


@pytest.fixture
def sample_red_team_results(sample_vulnerability_set):
    """Fixture that provides sample Red Team Agent results for testing."""
    return {
        "vulnerabilities": sample_vulnerability_set,
        "vulnerability_count": len(sample_vulnerability_set),
        "analysis_timestamp": time.time(),
        "total_files_analyzed": 5,
        "repository_info": {
            "name": "test-repo",
            "owner": "test-user",
            "url": "https://github.com/test-user/test-repo",
        },
    }


@pytest.fixture
def mock_motivation_response():
    """Mock response from the OpenAI API for motivation analysis."""
    return {
        "primary_motivation": {
            "category": "CONVENIENCE",
            "description": "The developer chose to directly concatenate user input into the SQL query for simplicity and ease of implementation rather than using a more secure but complex parameterized query approach.",
        },
        "secondary_motivations": [
            {
                "category": "KNOWLEDGE_GAP",
                "description": "The developer may not have been aware of SQL injection vulnerabilities or the best practices to prevent them.",
            }
        ],
        "thought_process_analysis": "The developer likely prioritized getting the feature working quickly over security considerations. They may have been thinking about the functional requirements without considering the security implications of directly using user input in SQL queries.",
        "organizational_factors": [
            "Lack of security training for developers",
            "Absence of code review processes focusing on security",
            "Possible time pressure to deliver features",
        ],
        "confidence_level": "HIGH",
    }


@pytest.fixture
def mock_pattern_response():
    """Mock response for pattern analysis across multiple vulnerabilities."""
    return {
        "common_factors": [
            "Knowledge gaps in security best practices",
            "Prioritization of convenience over security",
            "Lack of systematic security review processes",
        ],
        "organizational_recommendations": [
            "Implement security training program for all developers",
            "Establish mandatory code reviews with security focus",
            "Integrate automated security scanning tools into the development pipeline",
            "Create clear security guidelines and standards for development",
        ],
        "confidence": "MEDIUM",
        "summary": "The vulnerabilities primarily stem from developers prioritizing functionality and convenience over security, often due to knowledge gaps about security best practices.",
    }


@patch("agents.motivation_analysis_agent.client.chat.completions.create")
def test_analyze_vulnerability_motivation(
    mock_openai_api, sample_vulnerability, mock_motivation_response
):
    """Test the analysis of a single vulnerability's motivation."""
    # Setup the mock response
    mock_completion = MagicMock()
    mock_completion.choices[0].message.content = json.dumps(mock_motivation_response)
    mock_openai_api.return_value = mock_completion

    # Test the function
    result = analyze_vulnerability_motivation(sample_vulnerability)

    # Verify the API was called
    mock_openai_api.assert_called_once()

    # Verify that GPT-4o model was used
    args, kwargs = mock_openai_api.call_args
    assert kwargs["model"] == "gpt-4o"

    # Verify the result structure
    assert "primary_motivation" in result
    assert "category" in result["primary_motivation"]
    assert "description" in result["primary_motivation"]
    assert "secondary_motivations" in result
    assert "thought_process_analysis" in result
    assert "organizational_factors" in result
    assert "confidence_level" in result

    # Verify result content
    assert result["primary_motivation"]["category"] == "CONVENIENCE"
    assert len(result["secondary_motivations"]) > 0
    assert result["confidence_level"] == "HIGH"


@patch("agents.motivation_analysis_agent.analyze_vulnerability_motivation")
@patch("agents.motivation_analysis_agent.analyze_motivation_patterns")
def test_analyze_vulnerability_set(
    mock_analyze_patterns,
    mock_analyze_motivation,
    sample_vulnerability_set,
    mock_motivation_response,
    mock_pattern_response,
):
    """Test the analysis of multiple vulnerabilities."""
    # Setup mocks
    mock_analyze_motivation.return_value = mock_motivation_response
    mock_analyze_patterns.return_value = mock_pattern_response

    # Test the function
    result = analyze_vulnerability_set(sample_vulnerability_set)

    # Verify the result structure
    assert "analysis_timestamp" in result
    assert "analysis_duration_seconds" in result
    assert "vulnerabilities_analyzed" in result
    assert "individual_analyses" in result
    assert "pattern_analysis" in result

    # Verify result content
    assert result["vulnerabilities_analyzed"] == len(sample_vulnerability_set)
    assert len(result["individual_analyses"]) == len(sample_vulnerability_set)
    assert mock_analyze_motivation.call_count == len(sample_vulnerability_set)


@patch("agents.motivation_analysis_agent.client.chat.completions.create")
def test_analyze_motivation_patterns(mock_openai_api, mock_pattern_response):
    """Test the pattern analysis across multiple vulnerabilities."""
    # Prepare test data - list of motivation analyses
    motivation_analyses = [
        {
            "vulnerability": {
                "description": "SQL Injection",
                "type": "Injection",
                "severity": "CRITICAL",
            },
            "motivation_analysis": {
                "primary_motivation": {
                    "category": "CONVENIENCE",
                    "description": "Easy implementation",
                }
            },
        },
        {
            "vulnerability": {
                "description": "Hardcoded API key",
                "type": "Credentials",
                "severity": "HIGH",
            },
            "motivation_analysis": {
                "primary_motivation": {
                    "category": "KNOWLEDGE_GAP",
                    "description": "Unaware of security risks",
                }
            },
        },
        {
            "vulnerability": {
                "description": "Insecure deserialization",
                "type": "Deserialization",
                "severity": "CRITICAL",
            },
            "motivation_analysis": {
                "primary_motivation": {
                    "category": "CONVENIENCE",
                    "description": "Quick implementation",
                }
            },
        },
    ]

    # Setup the mock response
    mock_completion = MagicMock()
    mock_completion.choices[0].message.content = json.dumps(mock_pattern_response)
    mock_openai_api.return_value = mock_completion

    # Test the function with sorted motivations (pre-calculated)
    sorted_motivations = [("CONVENIENCE", 2), ("KNOWLEDGE_GAP", 1)]
    result = analyze_motivation_patterns(motivation_analyses)

    # Verify the API was called
    mock_openai_api.assert_called_once()

    # Verify result structure
    assert "primary_motivation_distribution" in result
    assert "common_factors" in result
    assert "organizational_recommendations" in result
    assert "confidence" in result

    # Verify result content
    assert "CONVENIENCE" in result["primary_motivation_distribution"]
    assert len(result["common_factors"]) > 0
    assert len(result["organizational_recommendations"]) > 0


def test_analyze_repository_results(sample_red_team_results, monkeypatch):
    """Test processing Red Team results for repository-level analysis."""

    # Mock the analyze_vulnerability_set function
    def mock_analyze_set(vulnerabilities):
        return {
            "analysis_timestamp": time.time(),
            "analysis_duration_seconds": 0.5,
            "vulnerabilities_analyzed": len(vulnerabilities),
            "individual_analyses": [{"vulnerability": v} for v in vulnerabilities],
            "pattern_analysis": {
                "primary_motivation_distribution": {
                    "CONVENIENCE": 2,
                    "KNOWLEDGE_GAP": 1,
                },
                "common_factors": ["Factor 1", "Factor 2"],
                "organizational_recommendations": ["Rec 1", "Rec 2"],
                "confidence": "MEDIUM",
            },
        }

    monkeypatch.setattr(
        "agents.motivation_analysis_agent.analyze_vulnerability_set", mock_analyze_set
    )

    # Test the function
    result = analyze_repository_results(sample_red_team_results)

    # Verify result structure
    assert "analysis_timestamp" in result
    assert "vulnerabilities_analyzed" in result
    assert "individual_analyses" in result
    assert "pattern_analysis" in result
    assert "repository_info" in result

    # Verify result content
    assert result["vulnerabilities_analyzed"] == len(
        sample_red_team_results["vulnerabilities"]
    )
    assert result["repository_info"] == sample_red_team_results["repository_info"]


def test_motivation_analysis_agent_function_with_repo_results(
    sample_red_team_results, monkeypatch
):
    """Test the main agent function with repository results as input."""

    # Mock the analyze_repository_results function
    def mock_analyze_repo(repo_results):
        return {
            "analysis_timestamp": time.time(),
            "vulnerabilities_analyzed": len(repo_results["vulnerabilities"]),
            "individual_analyses": [
                {"vulnerability": v} for v in repo_results["vulnerabilities"]
            ],
            "pattern_analysis": {
                "primary_motivation_distribution": {
                    "CONVENIENCE": 2,
                    "KNOWLEDGE_GAP": 1,
                },
            },
            "repository_info": repo_results["repository_info"],
        }

    monkeypatch.setattr(
        "agents.motivation_analysis_agent.analyze_repository_results", mock_analyze_repo
    )

    # Test the function
    result = motivation_analysis_agent_function(sample_red_team_results)

    # Verify result
    assert "vulnerabilities_analyzed" in result
    assert result["vulnerabilities_analyzed"] == len(
        sample_red_team_results["vulnerabilities"]
    )
    assert "repository_info" in result


def test_motivation_analysis_agent_function_with_single_vulnerability(
    sample_vulnerability, monkeypatch
):
    """Test the main agent function with a single vulnerability as input."""

    # Mock the analyze_vulnerability_motivation function
    def mock_analyze_vuln(vuln):
        return {
            "primary_motivation": {"category": "CONVENIENCE", "description": "Test"},
            "secondary_motivations": [],
            "thought_process_analysis": "Test analysis",
            "organizational_factors": ["Factor 1"],
            "confidence_level": "MEDIUM",
        }

    monkeypatch.setattr(
        "agents.motivation_analysis_agent.analyze_vulnerability_motivation",
        mock_analyze_vuln,
    )

    # Test the function
    result = motivation_analysis_agent_function(sample_vulnerability)

    # Verify result
    assert "vulnerabilities_analyzed" in result
    assert result["vulnerabilities_analyzed"] == 1
    assert "individual_analyses" in result
    assert len(result["individual_analyses"]) == 1


def test_motivation_analysis_agent_function_with_vulnerability_list(
    sample_vulnerability_set, monkeypatch
):
    """Test the main agent function with a list of vulnerabilities as input."""

    # Mock the analyze_vulnerability_set function
    def mock_analyze_set(vulns):
        return {
            "analysis_timestamp": time.time(),
            "vulnerabilities_analyzed": len(vulns),
            "individual_analyses": [{"vulnerability": v} for v in vulns],
            "pattern_analysis": {
                "primary_motivation_distribution": {
                    "CONVENIENCE": 2,
                    "KNOWLEDGE_GAP": 1,
                },
            },
        }

    monkeypatch.setattr(
        "agents.motivation_analysis_agent.analyze_vulnerability_set", mock_analyze_set
    )

    # Test the function
    result = motivation_analysis_agent_function(sample_vulnerability_set)

    # Verify result
    assert "vulnerabilities_analyzed" in result
    assert result["vulnerabilities_analyzed"] == len(sample_vulnerability_set)


def test_invalid_input_handling():
    """Test that the motivation analysis agent properly handles invalid inputs."""
    # Test with None
    result = motivation_analysis_agent_function(None)
    assert "error" in result

    # Test with empty dict
    result = motivation_analysis_agent_function({})
    assert "error" in result

    # Test with empty list
    result = motivation_analysis_agent_function([])
    assert "error" in result

    # Test with invalid structure
    result = motivation_analysis_agent_function({"invalid_key": "value"})
    assert "error" in result


def test_caching():
    """Test the caching decorator functionality."""

    # Create a test function with the cache decorator
    call_count = 0

    @cache_api_call
    def cached_test_function(arg):
        nonlocal call_count
        call_count += 1
        return f"Result for {arg}"

    # First call - should execute the function
    result1 = cached_test_function("test_arg")
    assert result1 == "Result for test_arg"
    assert call_count == 1

    # Second call with same arg - should use cache
    result2 = cached_test_function("test_arg")
    assert result2 == "Result for test_arg"
    assert call_count == 1  # Count shouldn't increase

    # Call with different arg - should execute the function
    result3 = cached_test_function("different_arg")
    assert result3 == "Result for different_arg"
    assert call_count == 2  # Count should increase


@pytest.mark.integration
def test_integration_with_red_team_agent():
    """
    Integration test verifying that the Motivation Analysis Agent properly processes
    Red Team Agent output. This test is marked as an integration test.
    """
    # Only run if API key is available and integration tests are enabled
    if not os.getenv("OPENAI_API_KEY") or not os.getenv("RUN_INTEGRATION_TESTS"):
        pytest.skip("Skipping integration test - API key or flag not set")

    # Sample vulnerable code
    test_code = """
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

    # Step 1: Get Red Team Agent results
    red_team_results = analyze_code_with_openai(test_code, "test_file.py")

    # Verify Red Team found vulnerabilities
    assert "vulnerabilities" in red_team_results
    assert len(red_team_results["vulnerabilities"]) > 0

    # Step 2: Pass vulnerabilities to Motivation Analysis Agent
    motivation_results = motivation_analysis_agent_function(
        red_team_results["vulnerabilities"]
    )

    # Verify motivation analysis worked
    assert "vulnerabilities_analyzed" in motivation_results
    assert motivation_results["vulnerabilities_analyzed"] > 0
    assert "individual_analyses" in motivation_results
    assert "pattern_analysis" in motivation_results

    # Save results to test_results directory
    output_dir = Path("test_results")
    output_dir.mkdir(exist_ok=True)
    output_file = output_dir / "motivation_analysis_integration_test_results.json"

    with open(output_file, "w", encoding="utf-8") as f:
        # Include timestamp and test details
        full_results = {
            "test_timestamp": datetime.now().isoformat(),
            "test_description": "Integration test between Red Team and Motivation Analysis agents",
            "red_team_results": red_team_results,
            "motivation_results": motivation_results,
        }
        json.dump(full_results, f, indent=2, default=str)

    print(f"Results saved to {output_file}")


@pytest.mark.integration
def test_end_to_end_analysis_flow():
    """
    End-to-end test of the full flow from code analysis through vulnerability detection
    to motivation analysis. This test is marked as an integration test.
    """
    # Only run if API key is available and integration tests are enabled
    if not os.getenv("OPENAI_API_KEY") or not os.getenv("RUN_INTEGRATION_TESTS"):
        pytest.skip("Skipping integration test - API key or flag not set")

    # Create a temporary file with vulnerable code
    with tempfile.NamedTemporaryFile(suffix=".py", delete=False) as temp_file:
        code_content = """
        def load_user_data(user_id):
            # Insecure function that loads user data
            import pickle
            from urllib.request import urlopen
            
            # Get the user data URL
            user_data_url = f"https://example.com/users/{user_id}/data"
            
            # Insecurely load data directly from URL
            with urlopen(user_data_url) as f:
                user_data = pickle.load(f)  # Insecure deserialization
                
            return user_data
            
        def authenticate_user(username, password):
            # Hard-coded credentials for testing
            admin_user = "admin"
            admin_pass = "super_secret_password123"
            
            # Insecure direct comparison
            if username == admin_user and password == admin_pass:
                return True
            else:
                return False
        """
        temp_file.write(code_content.encode())
        temp_path = temp_file.name

    try:
        # Step 1: Analyze file with Red Team Agent
        red_team_results = analyze_file(temp_path, code_content)

        # Verify Red Team found vulnerabilities
        assert "vulnerabilities" in red_team_results
        assert len(red_team_results["vulnerabilities"]) > 0

        # Step 2: Pass results to Motivation Analysis Agent
        motivation_results = analyze_repository_results(
            {"vulnerabilities": red_team_results["vulnerabilities"]}
        )

        # Verify motivation analysis worked
        assert "individual_analyses" in motivation_results
        assert "pattern_analysis" in motivation_results

        # Save full results to test_results directory
        output_dir = Path("test_results")
        output_dir.mkdir(exist_ok=True)
        output_file = output_dir / "end_to_end_analysis_test_results.json"

        with open(output_file, "w", encoding="utf-8") as f:
            full_results = {
                "test_timestamp": datetime.now().isoformat(),
                "test_description": "End-to-end test of Red Team and Motivation Analysis flow",
                "analyzed_file": os.path.basename(temp_path),
                "red_team_results": red_team_results,
                "motivation_results": motivation_results,
            }
            json.dump(full_results, f, indent=2, default=str)

        print(f"End-to-end test results saved to {output_file}")

    finally:
        # Clean up the temporary file
        os.unlink(temp_path)


if __name__ == "__main__":
    # Set the environment variable for integration tests if running directly
    os.environ["RUN_INTEGRATION_TESTS"] = "1"
    pytest.main(["-xvs", __file__])
