"""
Motivation Analysis Agent for Agent Purple

This module implements the Motivation Analysis Agent, which analyzes vulnerabilities
identified by the Red Team Agent and infers possible developer motivations behind
the code issues using the OpenAI API.
"""

import os
import json
import logging
import hashlib
from typing import Dict, List, Any, Optional, Union
import functools
import time

from openai import OpenAI
from dotenv import load_dotenv

# Configure logging
logging.basicConfig(
    level=logging.INFO, format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger(__name__)

# Load environment variables
load_dotenv()
OPENAI_API_KEY = os.getenv("OPENAI_API_KEY")

# Initialize OpenAI client
client = OpenAI(api_key=OPENAI_API_KEY)

# Cache for OpenAI API calls to prevent redundant requests
api_cache = {}

# Constants for motivation categories
MOTIVATION_CATEGORIES = {
    "CONVENIENCE": "Developer chose to implement a solution that was simpler or faster to code",
    "PERFORMANCE": "Developer prioritized system performance over security",
    "KNOWLEDGE_GAP": "Developer lacked necessary security knowledge or awareness",
    "DEADLINE_PRESSURE": "Developer was under time pressure to deliver functionality",
    "OVERSIGHT": "Developer overlooked potential security implications",
    "TESTING": "Code was intended for testing purposes, not production",
    "LEGACY": "Code was inherited from legacy systems or practices",
    "ABSTRACTION_TRUST": "Developer trusted an underlying framework or library without verification",
}


def cache_api_call(func):
    """Decorator to cache API responses based on input parameters."""

    @functools.wraps(func)
    def wrapper(*args, **kwargs):
        # Create a cache key based on the function arguments
        key_parts = [str(arg) for arg in args]
        key_parts.extend([f"{k}:{v}" for k, v in sorted(kwargs.items())])
        cache_key = hashlib.md5(str(key_parts).encode()).hexdigest()

        # Check if result is in cache
        if cache_key in api_cache:
            logger.info(f"Using cached result for {func.__name__}")
            return api_cache[cache_key]

        # Call the function and cache the result
        result = func(*args, **kwargs)
        api_cache[cache_key] = result
        return result

    return wrapper


@cache_api_call
def analyze_vulnerability_motivation(vulnerability: Dict[str, Any]) -> Dict[str, Any]:
    """
    Use OpenAI API to analyze a vulnerability and infer possible developer motivations.

    Args:
        vulnerability: Dictionary containing vulnerability information from Red Team Agent

    Returns:
        Dictionary containing inferred motivations for the vulnerability
    """
    try:
        logger.info(
            f"Analyzing motivation for vulnerability: {vulnerability.get('description', 'Unknown vulnerability')}"
        )

        # Extract relevant information from the vulnerability
        vulnerability_description = vulnerability.get("description", "")
        vulnerability_type = vulnerability.get("vulnerability_type", "")
        severity = vulnerability.get("severity", "")
        ai_impact = vulnerability.get("ai_impact", "")
        code_snippet = ""
        if "line_numbers" in vulnerability and vulnerability.get("code_context"):
            code_snippet = vulnerability.get("code_context", "")

        # Create context for framework mappings
        framework_context = ""
        if "framework_mappings" in vulnerability:
            mappings = vulnerability["framework_mappings"]

            # Add MITRE ATT&CK context
            attack = mappings.get("mitre_attack", {})
            if attack:
                framework_context += "\nMITRE ATT&CK Context:\n"
                if "tactics" in attack and attack["tactics"]:
                    tactics = [
                        f"{t.get('id', '')} - {t.get('name', '')}"
                        for t in attack["tactics"]
                    ]
                    framework_context += f"Tactics: {', '.join(tactics)}\n"
                if "techniques" in attack and attack["techniques"]:
                    techniques = [
                        f"{t.get('id', '')} - {t.get('name', '')}"
                        for t in attack["techniques"]
                    ]
                    framework_context += f"Techniques: {', '.join(techniques)}\n"
                if "explanation" in attack:
                    framework_context += (
                        f"Explanation: {attack.get('explanation', '')}\n"
                    )

            # Add MITRE ATLAS context
            atlas = mappings.get("mitre_atlas", {})
            if atlas:
                framework_context += "\nMITRE ATLAS Context:\n"
                if "tactics" in atlas and atlas["tactics"]:
                    tactics = [
                        f"{t.get('id', '')} - {t.get('name', '')}"
                        for t in atlas["tactics"]
                    ]
                    framework_context += f"Tactics: {', '.join(tactics)}\n"
                if "techniques" in atlas and atlas["techniques"]:
                    techniques = [
                        f"{t.get('id', '')} - {t.get('name', '')}"
                        for t in atlas["techniques"]
                    ]
                    framework_context += f"Techniques: {', '.join(techniques)}\n"
                if "explanation" in atlas:
                    framework_context += (
                        f"Explanation: {atlas.get('explanation', '')}\n"
                    )

        # Construct prompt for motivation analysis
        prompt = f"""
        Analyze this security vulnerability and infer the most likely developer motivations behind the code that led to this issue.
        
        Vulnerability Information:
        - Description: {vulnerability_description}
        - Type: {vulnerability_type}
        - Severity: {severity}
        - AI System Impact: {ai_impact}
        {framework_context}
        
        {f'Code snippet with vulnerability:\n```\n{code_snippet}\n```' if code_snippet else ''}
        
        For this vulnerability, provide:
        1. The primary motivation category (choose one from this list: CONVENIENCE, PERFORMANCE, KNOWLEDGE_GAP, DEADLINE_PRESSURE, OVERSIGHT, TESTING, LEGACY, ABSTRACTION_TRUST)
        2. Supporting motivation categories (0-3 additional categories from the same list that might apply)
        3. A detailed explanation of why the developer likely introduced this vulnerability
        4. A psychological analysis of the thought process that may have led to this vulnerability
        5. Possible organizational or environmental factors that could have contributed
        
        Format your response as a valid JSON with the following structure:
        {{
            "primary_motivation": {{
                "category": "CATEGORY_NAME",
                "description": "Detailed description of this motivation specific to this vulnerability"
            }},
            "secondary_motivations": [
                {{
                    "category": "CATEGORY_NAME",
                    "description": "Detailed description of this motivation specific to this vulnerability"
                }}
            ],
            "thought_process_analysis": "Detailed analysis of the developer's thought process",
            "organizational_factors": [
                "Factor 1 that may have contributed to this vulnerability",
                "Factor 2 that may have contributed to this vulnerability"
            ],
            "confidence_level": "HIGH|MEDIUM|LOW"
        }}
        
        Focus on being empathetic and understanding of the developer's perspective, avoiding blame or judgment.
        """

        # Call OpenAI API using GPT-4o model
        response = client.chat.completions.create(
            model="gpt-4o",  # Using GPT-4o for better analysis
            messages=[
                {
                    "role": "system",
                    "content": "You are an expert in software development psychology and security mindsets. Your task is to analyze security vulnerabilities and infer the likely developer motivations behind them.",
                },
                {"role": "user", "content": prompt},
            ],
            temperature=0.3,  # Lower temperature for more consistent responses
            max_tokens=1500,
        )

        # Extract and parse the response
        result_text = response.choices[0].message.content

        # Extract JSON from the response (in case there's any extra text)
        json_start = result_text.find("{")
        json_end = result_text.rfind("}") + 1
        if json_start >= 0 and json_end > json_start:
            json_str = result_text[json_start:json_end]
            motivation_result = json.loads(json_str)
        else:
            # Fallback if no JSON is found
            logger.warning("No valid JSON found in API response")
            motivation_result = {
                "primary_motivation": {
                    "category": "KNOWLEDGE_GAP",
                    "description": "Could not determine specific motivation from API response.",
                },
                "secondary_motivations": [],
                "thought_process_analysis": "Analysis unavailable.",
                "organizational_factors": [],
                "confidence_level": "LOW",
            }

        # Add category descriptions for reference
        if (
            "primary_motivation" in motivation_result
            and "category" in motivation_result["primary_motivation"]
        ):
            category = motivation_result["primary_motivation"]["category"]
            motivation_result["primary_motivation"]["category_description"] = (
                MOTIVATION_CATEGORIES.get(category, "Unknown category")
            )

        for motivation in motivation_result.get("secondary_motivations", []):
            if "category" in motivation:
                category = motivation["category"]
                motivation["category_description"] = MOTIVATION_CATEGORIES.get(
                    category, "Unknown category"
                )

        return motivation_result

    except Exception as e:
        logger.error(f"Error analyzing motivation with OpenAI: {str(e)}")
        return {
            "primary_motivation": {
                "category": "UNKNOWN",
                "description": "Could not determine motivation due to an error.",
            },
            "secondary_motivations": [],
            "thought_process_analysis": f"Analysis failed due to error: {str(e)}",
            "organizational_factors": [],
            "confidence_level": "LOW",
            "error": str(e),
        }


def analyze_vulnerability_set(vulnerabilities: List[Dict[str, Any]]) -> Dict[str, Any]:
    """
    Analyze a set of vulnerabilities to identify patterns in developer motivations.

    Args:
        vulnerabilities: List of vulnerability dictionaries from Red Team Agent

    Returns:
        Dictionary containing individual motivation analyses and overall patterns
    """
    start_time = time.time()
    logger.info(
        f"Starting motivation analysis for {len(vulnerabilities)} vulnerabilities"
    )

    # Analyze each vulnerability
    motivation_analyses = []
    for vulnerability in vulnerabilities:
        # Skip vulnerabilities without proper information
        if not isinstance(vulnerability, dict) or "description" not in vulnerability:
            logger.warning("Skipping invalid vulnerability without description")
            continue

        # Analyze the vulnerability
        try:
            motivation = analyze_vulnerability_motivation(vulnerability)

            # Add the vulnerability info to the motivation result for reference
            result = {
                "vulnerability": {
                    "description": vulnerability.get("description", ""),
                    "type": vulnerability.get("vulnerability_type", ""),
                    "severity": vulnerability.get("severity", ""),
                    "file_path": vulnerability.get("file_path", ""),
                },
                "motivation_analysis": motivation,
            }

            motivation_analyses.append(result)
        except Exception as e:
            logger.error(f"Error analyzing vulnerability: {str(e)}")

    # Identify patterns across all vulnerabilities
    pattern_analysis = analyze_motivation_patterns(motivation_analyses)

    elapsed_time = time.time() - start_time
    logger.info(f"Completed motivation analysis in {elapsed_time:.2f} seconds")

    return {
        "analysis_timestamp": time.time(),
        "analysis_duration_seconds": elapsed_time,
        "vulnerabilities_analyzed": len(motivation_analyses),
        "individual_analyses": motivation_analyses,
        "pattern_analysis": pattern_analysis,
    }


@cache_api_call
def analyze_motivation_patterns(
    motivation_analyses: List[Dict[str, Any]],
) -> Dict[str, Any]:
    """
    Identify patterns in developer motivations across multiple vulnerabilities.

    Args:
        motivation_analyses: List of motivation analysis results

    Returns:
        Dictionary containing identified patterns and recommendations
    """
    if not motivation_analyses:
        return {
            "primary_motivation_distribution": {},
            "common_factors": [],
            "organizational_recommendations": [],
            "confidence": "LOW",
        }

    try:
        # Count primary motivations
        motivation_counts = {}
        for analysis in motivation_analyses:
            motivation = analysis.get("motivation_analysis", {}).get(
                "primary_motivation", {}
            )
            category = motivation.get("category", "UNKNOWN")
            motivation_counts[category] = motivation_counts.get(category, 0) + 1

        # Sort by frequency
        sorted_motivations = sorted(
            motivation_counts.items(), key=lambda x: x[1], reverse=True
        )

        # Simple pattern analysis for small sets (fewer than 3 vulnerabilities)
        if len(motivation_analyses) < 3:
            common_factors = ["Insufficient data for comprehensive pattern analysis"]
            recommendations = [
                "Gather more vulnerability data for better pattern analysis"
            ]
            return {
                "primary_motivation_distribution": dict(sorted_motivations),
                "common_factors": common_factors,
                "organizational_recommendations": recommendations,
                "confidence": "LOW",
            }

        # For larger sets, use OpenAI to identify patterns
        return analyze_patterns_with_openai(motivation_analyses, sorted_motivations)

    except Exception as e:
        logger.error(f"Error in pattern analysis: {str(e)}")
        return {
            "primary_motivation_distribution": {},
            "common_factors": [f"Error during pattern analysis: {str(e)}"],
            "organizational_recommendations": ["Review individual analyses manually"],
            "confidence": "LOW",
            "error": str(e),
        }


@cache_api_call
def analyze_patterns_with_openai(
    motivation_analyses: List[Dict[str, Any]], sorted_motivations: List[tuple]
) -> Dict[str, Any]:
    """
    Use OpenAI to identify patterns in developer motivations across vulnerabilities.

    Args:
        motivation_analyses: List of motivation analysis results
        sorted_motivations: List of (category, count) tuples sorted by frequency

    Returns:
        Dictionary containing identified patterns and recommendations
    """
    try:
        # Prepare summary for pattern analysis
        motivation_summary = "\n".join(
            [
                f"- {category}: {count} vulnerabilities"
                for category, count in sorted_motivations
            ]
        )

        # Prepare vulnerabilities summary (limit to top 10 for context length)
        vulns_context = []
        for i, analysis in enumerate(motivation_analyses[:10]):
            vuln = analysis.get("vulnerability", {})
            motivation = analysis.get("motivation_analysis", {}).get(
                "primary_motivation", {}
            )

            vuln_summary = (
                f"Vulnerability {i+1}: {vuln.get('description', 'Unknown')}\n"
                f"Type: {vuln.get('type', 'Unknown')}, Severity: {vuln.get('severity', 'Unknown')}\n"
                f"Primary Motivation: {motivation.get('category', 'Unknown')} - {motivation.get('description', 'No description')}"
            )
            vulns_context.append(vuln_summary)

        vulnerabilities_summary = "\n\n".join(vulns_context)

        # Create the prompt
        prompt = f"""
        Analyze the following developer motivation patterns across multiple vulnerabilities:
        
        Motivation Distribution:
        {motivation_summary}
        
        Vulnerability Details (sample):
        {vulnerabilities_summary}
        
        Based on this information, please:
        1. Identify common underlying factors that might explain these patterns
        2. Suggest organizational improvements that could address these root causes
        3. Assess your confidence level in this analysis
        
        Format your response as valid JSON with the following structure:
        {{
            "common_factors": [
                "Detailed description of factor 1",
                "Detailed description of factor 2",
                "Detailed description of factor 3"
            ],
            "organizational_recommendations": [
                "Specific recommendation 1",
                "Specific recommendation 2",
                "Specific recommendation 3",
                "Specific recommendation 4"
            ],
            "confidence": "HIGH|MEDIUM|LOW",
            "summary": "Brief summary paragraph of the overall motivation patterns"
        }}
        """

        # Call OpenAI API
        response = client.chat.completions.create(
            model="gpt-4o",
            messages=[
                {
                    "role": "system",
                    "content": "You are an expert in software security psychology and organizational improvement. Your task is to analyze patterns in developer motivations behind security vulnerabilities and suggest improvements.",
                },
                {"role": "user", "content": prompt},
            ],
            temperature=0.4,
            max_tokens=1500,
        )

        # Parse the response
        result_text = response.choices[0].message.content
        json_start = result_text.find("{")
        json_end = result_text.rfind("}") + 1

        if json_start >= 0 and json_end > json_start:
            json_str = result_text[json_start:json_end]
            pattern_result = json.loads(json_str)
        else:
            logger.warning("No valid JSON found in pattern analysis response")
            pattern_result = {
                "common_factors": ["Could not extract valid pattern analysis"],
                "organizational_recommendations": [
                    "Review individual analyses manually"
                ],
                "confidence": "LOW",
                "summary": "Pattern analysis failed to produce valid results",
            }

        # Add the motivation distribution to the result
        pattern_result["primary_motivation_distribution"] = dict(sorted_motivations)

        return pattern_result

    except Exception as e:
        logger.error(f"Error analyzing patterns with OpenAI: {str(e)}")
        return {
            "primary_motivation_distribution": dict(sorted_motivations),
            "common_factors": [f"Error during pattern analysis: {str(e)}"],
            "organizational_recommendations": ["Review individual analyses manually"],
            "confidence": "LOW",
            "summary": "Pattern analysis failed due to an error",
            "error": str(e),
        }


def analyze_repository_results(red_team_results: Dict[str, Any]) -> Dict[str, Any]:
    """
    Process Red Team Agent's repository analysis results to infer developer motivations.

    Args:
        red_team_results: Dictionary containing Red Team Agent's analysis of a repository

    Returns:
        Dictionary containing motivation analysis results for the repository
    """
    start_time = time.time()
    logger.info("Starting repository motivation analysis")

    # Extract vulnerabilities from Red Team Agent results
    vulnerabilities = red_team_results.get("vulnerabilities", [])

    if not vulnerabilities:
        logger.info("No vulnerabilities found in repository to analyze")
        return {
            "analysis_timestamp": time.time(),
            "vulnerabilities_analyzed": 0,
            "analysis_duration_seconds": time.time() - start_time,
            "individual_analyses": [],
            "pattern_analysis": {
                "primary_motivation_distribution": {},
                "common_factors": ["No vulnerabilities to analyze"],
                "organizational_recommendations": [],
                "confidence": "NONE",
            },
        }

    # Analyze the vulnerabilities
    motivation_results = analyze_vulnerability_set(vulnerabilities)

    # Add repository info
    motivation_results["repository_info"] = red_team_results.get("repository_info", {})

    elapsed_time = time.time() - start_time
    logger.info(
        f"Completed repository motivation analysis in {elapsed_time:.2f} seconds"
    )

    return motivation_results


def motivation_analysis_agent_function(
    input_data: Union[Dict[str, Any], List[Dict[str, Any]]],
) -> Dict[str, Any]:
    """
    Main entry point for the Motivation Analysis Agent that can be used with AutoGen.

    Args:
        input_data: Either a dictionary of Red Team results or a list of vulnerabilities

    Returns:
        Dictionary containing motivation analysis results
    """
    try:
        logger.info("Motivation Analysis Agent started")

        # Handle different input types
        if isinstance(input_data, dict):
            # If input is Red Team repository results
            if "vulnerabilities" in input_data and isinstance(
                input_data["vulnerabilities"], list
            ):
                logger.info("Processing Red Team repository results")
                return analyze_repository_results(input_data)

            # If input is a single vulnerability
            elif "description" in input_data and "vulnerability_type" in input_data:
                logger.info("Processing single vulnerability")
                motivation = analyze_vulnerability_motivation(input_data)
                return {
                    "analysis_timestamp": time.time(),
                    "vulnerabilities_analyzed": 1,
                    "individual_analyses": [
                        {
                            "vulnerability": {
                                "description": input_data.get("description", ""),
                                "type": input_data.get("vulnerability_type", ""),
                                "severity": input_data.get("severity", ""),
                            },
                            "motivation_analysis": motivation,
                        }
                    ],
                }

        # If input is a list of vulnerabilities
        elif (
            isinstance(input_data, list)
            and input_data
            and isinstance(input_data[0], dict)
        ):
            logger.info(f"Processing list of {len(input_data)} vulnerabilities")
            return analyze_vulnerability_set(input_data)

        # Invalid input
        logger.error("Invalid input format for Motivation Analysis Agent")
        return {
            "error": "Invalid input format",
            "message": "Expected a Red Team result dictionary or a list of vulnerabilities",
            "analysis_timestamp": time.time(),
        }

    except Exception as e:
        logger.error(f"Error in motivation_analysis_agent_function: {str(e)}")
        return {
            "error": str(e),
            "analysis_timestamp": time.time(),
            "message": "An error occurred during motivation analysis",
        }


def main():
    """
    Test function to demonstrate using the Motivation Analysis Agent.
    """
    # Sample vulnerability from Red Team Agent
    test_vulnerability = {
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

    # Analyze the vulnerability
    result = analyze_vulnerability_motivation(test_vulnerability)
    print(json.dumps(result, indent=2))

    # Test with a set of vulnerabilities
    test_vulnerabilities = [
        test_vulnerability,
        {
            "description": "Hardcoded API key in source code",
            "severity": "HIGH",
            "line_numbers": [14],
            "vulnerability_type": "Credentials Management",
            "exploitation_scenarios": "API key could be extracted from source code and misused",
            "ai_impact": "Could allow unauthorized access to AI services or models",
        },
    ]

    set_result = analyze_vulnerability_set(test_vulnerabilities)
    print(json.dumps(set_result, indent=2))


if __name__ == "__main__":
    main()
