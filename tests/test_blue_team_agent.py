"""
Tests for the Blue Team Agent functionality.

This module contains tests for verifying that the Blue Team Agent correctly generates
remediation strategies and code fixes for vulnerabilities identified by the Red Team Agent,
taking into account developer motivations analyzed by the Motivation Analysis Agent.
"""

import os
import json
import pytest
import time
from unittest.mock import patch, MagicMock
import tempfile
from pathlib import Path
from datetime import datetime

# Import the Blue Team Agent module
from agents.blue_team_agent import (
    generate_vulnerability_fix,
    generate_fixes_for_vulnerability_set,
    generate_overall_recommendations,
    process_repository_results,
    blue_team_agent_function,
    cache_api_call,
)


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
            "code_context": """
def process_user_input(user_input):
    # This function processes user input for an AI model
    sql_query = "SELECT * FROM users WHERE username = '" + user_input + "'"
    return execute_query(sql_query)
            """,
        },
        {
            "description": "Hardcoded API key in source code",
            "severity": "HIGH",
            "line_numbers": [14],
            "vulnerability_type": "Credentials Management",
            "exploitation_scenarios": "API key could be extracted from source code and misused",
            "ai_impact": "Could allow unauthorized access to AI services or models",
            "code_context": """
def train_model(data_path):
    # Load training data
    training_data = load_data(data_path)
    
    # Initialize model
    model = AIModel()
    
    # Train the model with hardcoded API key
    api_key = "sk_test_AbCdEfGhIjKlMnOpQrStUvWxYz123456"
    model.train(training_data, api_key=api_key)
    
    return model
            """,
        },
    ]


@pytest.fixture
def sample_motivation_analysis():
    """Fixture that provides a sample motivation analysis for testing."""
    return {
        "primary_motivation": {
            "category": "CONVENIENCE",
            "description": "Developer chose directly concatenating user input for simplicity",
        },
        "secondary_motivations": [
            {
                "category": "KNOWLEDGE_GAP",
                "description": "Developer likely unaware of SQL injection vulnerabilities",
            }
        ],
        "thought_process_analysis": "Prioritized functionality over security considerations",
        "organizational_factors": [
            "Lack of security training for developers",
            "Absence of code review processes focusing on security",
        ],
        "confidence_level": "HIGH",
    }


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
def sample_motivation_results(sample_vulnerability_set):
    """Fixture that provides sample Motivation Analysis Agent results for testing."""
    return {
        "vulnerabilities_analyzed": len(sample_vulnerability_set),
        "analysis_timestamp": time.time(),
        "individual_analyses": [
            {
                "vulnerability": {
                    "description": "SQL Injection vulnerability due to direct concatenation of user input",
                },
                "motivation_analysis": {
                    "primary_motivation": {
                        "category": "CONVENIENCE",
                        "description": "Developer chose directly concatenating user input for simplicity",
                    },
                    "secondary_motivations": [
                        {
                            "category": "KNOWLEDGE_GAP",
                            "description": "Developer likely unaware of SQL injection vulnerabilities",
                        }
                    ],
                    "thought_process_analysis": "Prioritized functionality over security considerations",
                    "organizational_factors": [
                        "Lack of security training for developers",
                        "Absence of code review processes focusing on security",
                    ],
                    "confidence_level": "HIGH",
                },
            },
            {
                "vulnerability": {"description": "Hardcoded API key in source code"},
                "motivation_analysis": {
                    "primary_motivation": {
                        "category": "CONVENIENCE",
                        "description": "Developer hardcoded API key for ease of implementation",
                    },
                    "secondary_motivations": [
                        {
                            "category": "DEADLINE_PRESSURE",
                            "description": "Developer may have been under time pressure",
                        }
                    ],
                    "thought_process_analysis": "Developer likely prioritized getting the functionality working quickly",
                    "organizational_factors": [
                        "Lack of secure credential management practices",
                        "Insufficient security reviews",
                    ],
                    "confidence_level": "HIGH",
                },
            },
        ],
        "pattern_analysis": {
            "primary_motivation_distribution": {
                "CONVENIENCE": 2,
                "KNOWLEDGE_GAP": 1,
                "DEADLINE_PRESSURE": 1,
            },
            "common_factors": [
                "Prioritization of functionality over security",
                "Lack of security awareness",
            ],
            "organizational_recommendations": [
                "Implement security training",
                "Establish code review practices",
            ],
            "confidence": "HIGH",
        },
    }


@pytest.fixture
def mock_fix_response():
    """Mock response from the OpenAI API for vulnerability fix generation."""
    return {
        "vulnerability_summary": "SQL Injection vulnerability through direct string concatenation",
        "fix_difficulty": "EASY",
        "code_level_fixes": [
            {
                "description": "Use parameterized queries instead of string concatenation",
                "code": """
def process_user_input(user_input):
    # This function processes user input for an AI model
    sql_query = "SELECT * FROM users WHERE username = ?"
    return execute_query(sql_query, (user_input,))
                """,
                "explanation": "Parameterized queries ensure that user input is treated as data, not executable SQL, preventing injection attacks",
            }
        ],
        "conceptual_recommendations": [
            "Always use parameterized queries or prepared statements for database operations",
            "Consider using an ORM (Object-Relational Mapping) library which handles SQL escaping automatically",
        ],
        "organizational_improvements": [
            "Implement security training focused on OWASP Top 10 vulnerabilities",
            "Establish mandatory code reviews with security-focused checklist",
        ],
        "security_standards": [
            "OWASP SQL Injection Prevention Cheat Sheet",
            "CWE-89: Improper Neutralization of Special Elements used in an SQL Command",
        ],
        "resources": [
            "OWASP SQL Injection Prevention Cheat Sheet - https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html",
            "NIST Guide to SQL Injection - https://nvd.nist.gov/vuln/detail/cve-2021-32626",
        ],
    }


@pytest.fixture
def mock_overall_recommendations_response():
    """Mock response for overall recommendations across multiple vulnerabilities."""
    return {
        "priority_actions": [
            "Implement parameterized queries for all database operations to prevent SQL injection",
            "Remove all hardcoded credentials from source code and use a secure credentials management system",
        ],
        "security_framework_recommendations": [
            "Implement OWASP ASVS (Application Security Verification Standard) for security requirements",
            "Follow NIST Cybersecurity Framework for holistic security program development",
        ],
        "training_recommendations": [
            "Conduct regular secure coding training sessions focusing on OWASP Top 10",
            "Implement hands-on security workshops for developers to practice secure coding techniques",
        ],
        "monitoring_recommendations": [
            "Implement SAST (Static Application Security Testing) tools in CI/CD pipeline",
            "Perform regular security code reviews with focus on AI-specific vulnerabilities",
        ],
        "executive_summary": "The application has critical security vulnerabilities that could compromise system integrity. Immediate action is required to implement parameterized queries and proper credential management, along with developer training and automated security testing.",
    }


@patch("agents.blue_team_agent.client.chat.completions.create")
def test_generate_vulnerability_fix(
    mock_openai_api, sample_vulnerability, mock_fix_response, sample_motivation_analysis
):
    """Test the generation of fixes for a single vulnerability."""
    # Setup the mock response
    mock_completion = MagicMock()
    mock_completion.choices[0].message.content = json.dumps(mock_fix_response)
    mock_openai_api.return_value = mock_completion

    # Test the function without motivation analysis
    result = generate_vulnerability_fix(sample_vulnerability)

    # Verify the API was called
    mock_openai_api.assert_called_once()

    # Verify that GPT-4o model was used
    args, kwargs = mock_openai_api.call_args
    assert kwargs["model"] == "gpt-4o"

    # Reset the mock
    mock_openai_api.reset_mock()
    mock_openai_api.return_value = mock_completion

    # Test with motivation analysis included
    result_with_motivation = generate_vulnerability_fix(
        sample_vulnerability, sample_motivation_analysis
    )

    # Verify the API was called with motivation context
    mock_openai_api.assert_called_once()
    args, kwargs = mock_openai_api.call_args
    assert "Motivation Analysis Context" in kwargs["messages"][1]["content"]

    # Verify result structure
    assert "vulnerability_summary" in result
    assert "fix_difficulty" in result
    assert "code_level_fixes" in result
    assert "conceptual_recommendations" in result
    assert "organizational_improvements" in result
    assert "security_standards" in result
    assert "resources" in result
    assert "vulnerability_id" in result
    assert "creation_timestamp" in result
    assert "severity" in result

    # Verify result content
    assert result["fix_difficulty"] == "EASY"
    assert len(result["code_level_fixes"]) > 0
    assert len(result["conceptual_recommendations"]) > 0
    assert result["severity"] == sample_vulnerability["severity"]


@patch("agents.blue_team_agent.generate_vulnerability_fix")
@patch("agents.blue_team_agent.generate_overall_recommendations")
def test_generate_fixes_for_vulnerability_set(
    mock_overall_recommendations,
    mock_generate_fix,
    sample_vulnerability_set,
    mock_fix_response,
    mock_overall_recommendations_response,
):
    """Test the generation of fixes for multiple vulnerabilities."""
    # Setup mocks
    mock_generate_fix.return_value = mock_fix_response
    mock_overall_recommendations.return_value = mock_overall_recommendations_response

    # Test the function
    result = generate_fixes_for_vulnerability_set(sample_vulnerability_set)

    # Verify the result structure
    assert "analysis_timestamp" in result
    assert "analysis_duration_seconds" in result
    assert "vulnerabilities_remediated" in result
    assert "individual_remediations" in result
    assert "overall_recommendations" in result

    # Verify result content
    assert result["vulnerabilities_remediated"] == len(sample_vulnerability_set)
    assert len(result["individual_remediations"]) == len(sample_vulnerability_set)
    assert mock_generate_fix.call_count == len(sample_vulnerability_set)

    # Test with motivation analyses included
    motivation_analyses = [
        {
            "vulnerability": {
                "description": "SQL Injection vulnerability due to direct concatenation of user input"
            },
            "motivation_analysis": {
                "primary_motivation": {"category": "CONVENIENCE"},
            },
        },
        {
            "vulnerability": {"description": "Hardcoded API key in source code"},
            "motivation_analysis": {
                "primary_motivation": {"category": "KNOWLEDGE_GAP"},
            },
        },
    ]

    # Reset the mock
    mock_generate_fix.reset_mock()
    mock_generate_fix.return_value = mock_fix_response

    # Test with motivation analyses
    result_with_motivation = generate_fixes_for_vulnerability_set(
        sample_vulnerability_set, motivation_analyses
    )

    # Verify the motivation analyses were used
    assert mock_generate_fix.call_count == len(sample_vulnerability_set)


@patch("agents.blue_team_agent.client.chat.completions.create")
def test_generate_overall_recommendations(
    mock_openai_api, mock_overall_recommendations_response
):
    """Test the generation of overall recommendations based on vulnerability fixes."""
    # Setup the mock response
    mock_completion = MagicMock()
    mock_completion.choices[0].message.content = json.dumps(
        mock_overall_recommendations_response
    )
    mock_openai_api.return_value = mock_completion

    # Prepare test data - list of fix results
    fix_results = [
        {
            "vulnerability": {
                "description": "SQL Injection",
                "type": "Injection",
                "severity": "CRITICAL",
            },
            "remediation": {
                "vulnerability_summary": "SQL Injection vulnerability",
                "fix_difficulty": "EASY",
            },
        },
        {
            "vulnerability": {
                "description": "Hardcoded API key",
                "type": "Credentials",
                "severity": "HIGH",
            },
            "remediation": {
                "vulnerability_summary": "Hardcoded credentials",
                "fix_difficulty": "EASY",
            },
        },
    ]

    # Test the function
    result = generate_overall_recommendations(fix_results)

    # Verify the API was called
    mock_openai_api.assert_called_once()

    # Verify result structure
    assert "priority_actions" in result
    assert "security_framework_recommendations" in result
    assert "training_recommendations" in result
    assert "monitoring_recommendations" in result
    assert "executive_summary" in result

    # Verify result content
    assert len(result["priority_actions"]) > 0
    assert len(result["security_framework_recommendations"]) > 0
    assert len(result["training_recommendations"]) > 0
    assert len(result["monitoring_recommendations"]) > 0


def test_process_repository_results(
    sample_red_team_results, sample_motivation_results, monkeypatch
):
    """Test processing Red Team and Motivation Analysis results for repository-level fixes."""

    # Mock the generate_fixes_for_vulnerability_set function
    def mock_generate_fixes(vulnerabilities, motivation_analyses=None):
        return {
            "analysis_timestamp": time.time(),
            "analysis_duration_seconds": 0.5,
            "vulnerabilities_remediated": len(vulnerabilities),
            "individual_remediations": [
                {"vulnerability": v, "remediation": {"fix_difficulty": "EASY"}}
                for v in vulnerabilities
            ],
            "overall_recommendations": {
                "priority_actions": ["Action 1", "Action 2"],
                "security_framework_recommendations": ["Framework Rec 1"],
                "training_recommendations": ["Training Rec 1"],
                "monitoring_recommendations": ["Monitoring Rec 1"],
            },
        }

    monkeypatch.setattr(
        "agents.blue_team_agent.generate_fixes_for_vulnerability_set",
        mock_generate_fixes,
    )

    # Test the function with just Red Team results
    result = process_repository_results(sample_red_team_results)

    # Verify result structure
    assert "analysis_timestamp" in result
    assert "vulnerabilities_remediated" in result
    assert "individual_remediations" in result
    assert "overall_recommendations" in result

    # Verify result content
    assert result["vulnerabilities_remediated"] == len(
        sample_red_team_results["vulnerabilities"]
    )

    # Test with Motivation Analysis results included
    result_with_motivation = process_repository_results(
        sample_red_team_results, sample_motivation_results
    )

    # Verify result structure matches
    assert "vulnerabilities_remediated" in result_with_motivation
    assert result_with_motivation["vulnerabilities_remediated"] == len(
        sample_red_team_results["vulnerabilities"]
    )


def test_blue_team_agent_function_with_repo_results(
    sample_red_team_results, sample_motivation_results, monkeypatch
):
    """Test the main agent function with repository results as input."""

    # Mock the process_repository_results function
    def mock_process_repo(repo_results, motivation_results=None):
        return {
            "analysis_timestamp": time.time(),
            "vulnerabilities_remediated": len(repo_results["vulnerabilities"]),
            "individual_remediations": [
                {"vulnerability": v, "remediation": {"fix_difficulty": "EASY"}}
                for v in repo_results["vulnerabilities"]
            ],
            "overall_recommendations": {
                "priority_actions": ["Action 1", "Action 2"],
            },
        }

    monkeypatch.setattr(
        "agents.blue_team_agent.process_repository_results", mock_process_repo
    )

    # Test the function
    result = blue_team_agent_function(sample_red_team_results)

    # Verify result
    assert "vulnerabilities_remediated" in result
    assert result["vulnerabilities_remediated"] == len(
        sample_red_team_results["vulnerabilities"]
    )

    # Test with motivation results
    result_with_motivation = blue_team_agent_function(
        sample_red_team_results, sample_motivation_results
    )

    # Verify result
    assert "vulnerabilities_remediated" in result_with_motivation
    assert result_with_motivation["vulnerabilities_remediated"] == len(
        sample_red_team_results["vulnerabilities"]
    )


def test_blue_team_agent_function_with_single_vulnerability(
    sample_vulnerability, sample_motivation_analysis, monkeypatch
):
    """Test the main agent function with a single vulnerability as input."""

    # Mock the generate_vulnerability_fix function
    def mock_generate_fix(vuln, motivation_analysis=None):
        return {
            "vulnerability_summary": vuln.get("description", ""),
            "fix_difficulty": "EASY",
            "code_level_fixes": [
                {
                    "description": "Test fix",
                    "code": "def fixed(): pass",
                    "explanation": "Test explanation",
                }
            ],
            "conceptual_recommendations": ["Rec 1"],
            "organizational_improvements": ["Improvement 1"],
            "security_standards": ["Standard 1"],
            "resources": ["Resource 1"],
            "vulnerability_id": "123",
            "creation_timestamp": time.time(),
            "severity": vuln.get("severity", ""),
        }

    monkeypatch.setattr(
        "agents.blue_team_agent.generate_vulnerability_fix", mock_generate_fix
    )

    # Test the function
    result = blue_team_agent_function(sample_vulnerability)

    # Verify result
    assert "vulnerabilities_remediated" in result
    assert result["vulnerabilities_remediated"] == 1
    assert "individual_remediations" in result
    assert len(result["individual_remediations"]) == 1

    # Test with motivation analysis
    result_with_motivation = blue_team_agent_function(
        sample_vulnerability, sample_motivation_analysis
    )

    # Verify result
    assert "vulnerabilities_remediated" in result_with_motivation
    assert result_with_motivation["vulnerabilities_remediated"] == 1


def test_blue_team_agent_function_with_vulnerability_list(
    sample_vulnerability_set, sample_motivation_results, monkeypatch
):
    """Test the main agent function with a list of vulnerabilities as input."""

    # Mock the generate_fixes_for_vulnerability_set function
    def mock_generate_fixes(vulns, motivation_analyses=None):
        return {
            "analysis_timestamp": time.time(),
            "analysis_duration_seconds": 0.5,
            "vulnerabilities_remediated": len(vulns),
            "individual_remediations": [
                {"vulnerability": v, "remediation": {"fix_difficulty": "EASY"}}
                for v in vulns
            ],
            "overall_recommendations": {
                "priority_actions": ["Action 1", "Action 2"],
            },
        }

    monkeypatch.setattr(
        "agents.blue_team_agent.generate_fixes_for_vulnerability_set",
        mock_generate_fixes,
    )

    # Test the function
    result = blue_team_agent_function(sample_vulnerability_set)

    # Verify result
    assert "vulnerabilities_remediated" in result
    assert result["vulnerabilities_remediated"] == len(sample_vulnerability_set)

    # Test with motivation analyses
    result_with_motivation = blue_team_agent_function(
        sample_vulnerability_set, sample_motivation_results
    )

    # Verify result
    assert "vulnerabilities_remediated" in result_with_motivation
    assert result_with_motivation["vulnerabilities_remediated"] == len(
        sample_vulnerability_set
    )


def test_invalid_input_handling():
    """Test that the blue team agent properly handles invalid inputs."""
    # Test with None
    result = blue_team_agent_function(None)
    assert "error" in result

    # Test with empty dict
    result = blue_team_agent_function({})
    assert "error" in result

    # Test with empty list
    result = blue_team_agent_function([])
    assert "error" in result

    # Test with invalid structure
    result = blue_team_agent_function({"invalid_key": "value"})
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


if __name__ == "__main__":
    pytest.main(["-xvs", __file__])
