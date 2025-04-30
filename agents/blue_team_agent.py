"""
Blue Team Agent for Agent Purple

This module implements the Blue Team Agent, which suggests remediation strategies and code fixes
for vulnerabilities identified by the Red Team Agent, taking into account developer motivations
identified by the Motivation Analysis Agent.
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
def generate_vulnerability_fix(
    vulnerability: Dict[str, Any], motivation_analysis: Optional[Dict[str, Any]] = None
) -> Dict[str, Any]:
    """
    Generate a fix for a specific vulnerability, optionally considering motivation analysis.

    Args:
        vulnerability: Dictionary containing vulnerability information from Red Team Agent
        motivation_analysis: Optional dictionary containing motivation analysis from Motivation Analysis Agent

    Returns:
        Dictionary containing suggested fixes and remediation strategies
    """
    try:
        logger.info(
            f"Generating fix for vulnerability: {vulnerability.get('description', 'Unknown vulnerability')}"
        )

        # Extract relevant information from the vulnerability
        vulnerability_description = vulnerability.get("description", "")
        vulnerability_type = vulnerability.get("vulnerability_type", "")
        severity = vulnerability.get("severity", "")
        ai_impact = vulnerability.get("ai_impact", "")
        line_numbers = vulnerability.get("line_numbers", [])
        file_path = vulnerability.get("file_path", "")
        exploitation_scenarios = vulnerability.get("exploitation_scenarios", "")

        # Extract code context if available
        code_snippet = ""
        if "code_context" in vulnerability:
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

        # Include motivation analysis context if available
        motivation_context = ""
        if motivation_analysis:
            primary_motivation = motivation_analysis.get("primary_motivation", {})
            secondary_motivations = motivation_analysis.get("secondary_motivations", [])
            thought_process = motivation_analysis.get("thought_process_analysis", "")
            org_factors = motivation_analysis.get("organizational_factors", [])

            motivation_context = f"""
Motivation Analysis Context:
- Primary Motivation: {primary_motivation.get('category', '')} - {primary_motivation.get('description', '')}
- Secondary Motivations: {', '.join([m.get('category', '') for m in secondary_motivations])}
- Thought Process: {thought_process}
- Organizational Factors: {', '.join(org_factors)}
"""

        # Construct prompt for generating fix
        prompt = f"""
        Generate a detailed remediation strategy for the following security vulnerability, focusing on both code-level fixes and organizational improvements.
        
        Vulnerability Information:
        - Description: {vulnerability_description}
        - Type: {vulnerability_type}
        - Severity: {severity}
        - AI System Impact: {ai_impact}
        - File Path: {file_path}
        - Line Numbers: {', '.join(map(str, line_numbers))}
        - Exploitation Scenarios: {exploitation_scenarios}
        {framework_context}
        {motivation_context}
        
        {f'Code snippet with vulnerability:\n```\n{code_snippet}\n```' if code_snippet else ''}
        
        For this vulnerability, provide:
        1. A concise explanation of why this is a vulnerability
        2. A code-level fix with secure code examples
        3. Conceptual recommendations to prevent similar vulnerabilities
        4. Long-term organizational improvements
        5. Relevant security best practices or standards to follow
        
        Format your response as a valid JSON with the following structure:
        {{
            "vulnerability_summary": "Brief summary of the vulnerability",
            "fix_difficulty": "EASY|MODERATE|COMPLEX",
            "code_level_fixes": [
                {{
                    "description": "Description of the fix",
                    "code": "Code snippet showing the fixed version",
                    "explanation": "Explanation of why this fix works"
                }}
            ],
            "conceptual_recommendations": [
                "Recommendation 1 with explanation",
                "Recommendation 2 with explanation"
            ],
            "organizational_improvements": [
                "Organizational improvement 1",
                "Organizational improvement 2"
            ],
            "security_standards": [
                "Relevant standard or best practice 1",
                "Relevant standard or best practice 2"
            ],
            "resources": [
                "Resource 1 - title and link",
                "Resource 2 - title and link"
            ]
        }}
        
        If providing multiple alternative fixes, include them as separate objects in the code_level_fixes array.
        """

        # Call OpenAI API using GPT-4o model
        response = client.chat.completions.create(
            model="gpt-4o",  # Using GPT-4o for better analysis
            messages=[
                {
                    "role": "system",
                    "content": "You are an expert in secure coding practices and remediation of security vulnerabilities in software systems, particularly AI systems. Your task is to provide detailed, actionable remediation strategies for identified vulnerabilities.",
                },
                {"role": "user", "content": prompt},
            ],
            temperature=0.3,  # Lower temperature for more consistent responses
            max_tokens=2000,
        )

        # Extract and parse the response
        result_text = response.choices[0].message.content

        # Extract JSON from the response (in case there's any extra text)
        json_start = result_text.find("{")
        json_end = result_text.rfind("}") + 1
        if json_start >= 0 and json_end > json_start:
            json_str = result_text[json_start:json_end]
            fix_result = json.loads(json_str)
        else:
            # Fallback if no JSON is found
            logger.warning("No valid JSON found in API response")
            fix_result = {
                "vulnerability_summary": vulnerability_description,
                "fix_difficulty": "MODERATE",
                "code_level_fixes": [
                    {
                        "description": "Could not generate specific code fix",
                        "code": "",
                        "explanation": "API response parsing failed",
                    }
                ],
                "conceptual_recommendations": ["Review vulnerability manually"],
                "organizational_improvements": ["Consult security expert"],
                "security_standards": [],
                "resources": [],
            }

        # Add metadata
        fix_result["vulnerability_id"] = vulnerability.get(
            "id", str(hash(vulnerability_description))
        )
        fix_result["creation_timestamp"] = time.time()
        fix_result["severity"] = severity

        return fix_result

    except Exception as e:
        logger.error(f"Error generating fix with OpenAI: {str(e)}")
        return {
            "vulnerability_summary": vulnerability.get(
                "description", "Unknown vulnerability"
            ),
            "fix_difficulty": "UNKNOWN",
            "code_level_fixes": [
                {
                    "description": "Error generating fix",
                    "code": "",
                    "explanation": f"Error: {str(e)}",
                }
            ],
            "conceptual_recommendations": ["Review vulnerability manually"],
            "organizational_improvements": ["Consult security expert"],
            "security_standards": [],
            "resources": [],
            "error": str(e),
            "creation_timestamp": time.time(),
            "severity": vulnerability.get("severity", "UNKNOWN"),
        }


def generate_fixes_for_vulnerability_set(
    vulnerabilities: List[Dict[str, Any]],
    motivation_analyses: Optional[List[Dict[str, Any]]] = None,
) -> Dict[str, Any]:
    """
    Generate fixes for a set of vulnerabilities, optionally considering motivation analyses.

    Args:
        vulnerabilities: List of vulnerability dictionaries from Red Team Agent
        motivation_analyses: Optional list of motivation analysis results from Motivation Analysis Agent

    Returns:
        Dictionary containing fixes for each vulnerability and overall recommendations
    """
    start_time = time.time()
    logger.info(
        f"Starting remediation generation for {len(vulnerabilities)} vulnerabilities"
    )

    # Create mapping between vulnerabilities and motivation analyses if provided
    motivation_map = {}
    if motivation_analyses:
        for analysis in motivation_analyses:
            if (
                "vulnerability" in analysis
                and "description" in analysis["vulnerability"]
            ):
                vuln_desc = analysis["vulnerability"].get("description", "")
                motivation_map[vuln_desc] = analysis.get("motivation_analysis", {})

    # Generate fix for each vulnerability
    fix_results = []
    for vulnerability in vulnerabilities:
        # Skip vulnerabilities without proper information
        if not isinstance(vulnerability, dict) or "description" not in vulnerability:
            logger.warning("Skipping invalid vulnerability without description")
            continue

        # Find corresponding motivation analysis if available
        motivation_analysis = motivation_map.get(vulnerability.get("description", ""))

        # Generate fix
        try:
            fix = generate_vulnerability_fix(vulnerability, motivation_analysis)
            fix_results.append(
                {
                    "vulnerability": {
                        "description": vulnerability.get("description", ""),
                        "type": vulnerability.get("vulnerability_type", ""),
                        "severity": vulnerability.get("severity", ""),
                        "file_path": vulnerability.get("file_path", ""),
                    },
                    "remediation": fix,
                }
            )
        except Exception as e:
            logger.error(f"Error generating fix for vulnerability: {str(e)}")

    # Generate comprehensive recommendations
    overall_recommendations = generate_overall_recommendations(fix_results)

    elapsed_time = time.time() - start_time
    logger.info(f"Completed remediation generation in {elapsed_time:.2f} seconds")

    return {
        "analysis_timestamp": time.time(),
        "analysis_duration_seconds": elapsed_time,
        "vulnerabilities_remediated": len(fix_results),
        "individual_remediations": fix_results,
        "overall_recommendations": overall_recommendations,
    }


@cache_api_call
def generate_overall_recommendations(
    fix_results: List[Dict[str, Any]],
) -> Dict[str, Any]:
    """
    Generate overall recommendations based on all vulnerability fixes.

    Args:
        fix_results: List of fix results for individual vulnerabilities

    Returns:
        Dictionary containing overall recommendations
    """
    if not fix_results:
        return {
            "priority_actions": [],
            "security_framework_recommendations": [],
            "training_recommendations": [],
            "monitoring_recommendations": [],
        }

    try:
        # Prepare summary of vulnerabilities and fixes
        vuln_summaries = []
        for i, result in enumerate(fix_results[:10]):  # Limit to 10 for context length
            vuln = result.get("vulnerability", {})
            remediation = result.get("remediation", {})

            summary = (
                f"Vulnerability {i+1}: {vuln.get('description', 'Unknown')}\n"
                f"Type: {vuln.get('type', 'Unknown')}, Severity: {vuln.get('severity', 'Unknown')}\n"
                f"Fix Difficulty: {remediation.get('fix_difficulty', 'Unknown')}"
            )
            vuln_summaries.append(summary)

        vulnerabilities_summary = "\n\n".join(vuln_summaries)

        # Create the prompt
        prompt = f"""
        Based on the following vulnerabilities and their fixes, provide comprehensive recommendations for improving the overall security posture of the AI system:
        
        Vulnerability Summary:
        {vulnerabilities_summary}
        
        Please provide:
        1. Prioritized actions that should be taken immediately
        2. Recommendations for implementing security frameworks or standards
        3. Training recommendations for the development team
        4. Monitoring and ongoing assessment recommendations
        
        Format your response as valid JSON with the following structure:
        {{
            "priority_actions": [
                "Detailed description of high-priority action 1",
                "Detailed description of high-priority action 2",
                "Detailed description of high-priority action 3"
            ],
            "security_framework_recommendations": [
                "Framework recommendation 1 with explanation",
                "Framework recommendation 2 with explanation"
            ],
            "training_recommendations": [
                "Training recommendation 1",
                "Training recommendation 2",
                "Training recommendation 3"
            ],
            "monitoring_recommendations": [
                "Monitoring recommendation 1",
                "Monitoring recommendation 2"
            ],
            "executive_summary": "A concise executive summary of the security situation and key recommendations"
        }}
        """

        # Call OpenAI API
        response = client.chat.completions.create(
            model="gpt-4o",
            messages=[
                {
                    "role": "system",
                    "content": "You are an expert in cybersecurity and secure AI system development. Your task is to provide strategic recommendations to improve the overall security posture of an organization based on identified vulnerabilities.",
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
            recommendations = json.loads(json_str)
        else:
            logger.warning("No valid JSON found in recommendations response")
            recommendations = {
                "priority_actions": ["Review individual vulnerability fixes manually"],
                "security_framework_recommendations": [
                    "Consider NIST Cybersecurity Framework"
                ],
                "training_recommendations": [
                    "Security awareness training for all developers"
                ],
                "monitoring_recommendations": ["Implement regular security scans"],
                "executive_summary": "System requires security review. See individual vulnerability fixes.",
            }

        return recommendations

    except Exception as e:
        logger.error(f"Error generating overall recommendations: {str(e)}")
        return {
            "priority_actions": ["Error generating recommendations"],
            "security_framework_recommendations": [],
            "training_recommendations": [],
            "monitoring_recommendations": [],
            "executive_summary": f"Error during analysis: {str(e)}",
            "error": str(e),
        }


def process_repository_results(
    red_team_results: Dict[str, Any],
    motivation_results: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """
    Process Red Team Agent's and Motivation Analysis Agent's results to generate fixes.

    Args:
        red_team_results: Dictionary containing Red Team Agent's analysis of a repository
        motivation_results: Optional dictionary containing Motivation Analysis Agent's results

    Returns:
        Dictionary containing remediation results for the repository
    """
    start_time = time.time()
    logger.info("Starting repository remediation generation")

    # Extract vulnerabilities from Red Team Agent results
    vulnerabilities = red_team_results.get("vulnerabilities", [])

    if not vulnerabilities:
        logger.info("No vulnerabilities found in repository to remediate")
        return {
            "analysis_timestamp": time.time(),
            "vulnerabilities_remediated": 0,
            "analysis_duration_seconds": time.time() - start_time,
            "individual_remediations": [],
            "overall_recommendations": {
                "priority_actions": [
                    "No vulnerabilities identified that require remediation"
                ],
                "security_framework_recommendations": [],
                "training_recommendations": [],
                "monitoring_recommendations": [],
                "executive_summary": "No vulnerabilities were identified in the repository.",
            },
        }

    # Extract motivation analyses if available
    motivation_analyses = None
    if motivation_results and "individual_analyses" in motivation_results:
        motivation_analyses = motivation_results.get("individual_analyses", [])

    # Generate fixes for the vulnerabilities
    fix_results = generate_fixes_for_vulnerability_set(
        vulnerabilities, motivation_analyses
    )

    # Add repository info
    if "repository_info" in red_team_results:
        fix_results["repository_info"] = red_team_results.get("repository_info", {})

    elapsed_time = time.time() - start_time
    logger.info(
        f"Completed repository remediation generation in {elapsed_time:.2f} seconds"
    )

    return fix_results


def blue_team_agent_function(
    input_data: Union[Dict[str, Any], List[Dict[str, Any]]],
    motivation_data: Optional[Union[Dict[str, Any], List[Dict[str, Any]]]] = None,
) -> Dict[str, Any]:
    """
    Main entry point for the Blue Team Agent that can be used with AutoGen.

    Args:
        input_data: Either a dictionary of Red Team results, a list of vulnerabilities, or a single vulnerability
        motivation_data: Optional motivation analysis data from the Motivation Analysis Agent

    Returns:
        Dictionary containing remediation results
    """
    try:
        logger.info("Blue Team Agent started")

        # Handle different input types
        if isinstance(input_data, dict):
            # If input is Red Team repository results
            if "vulnerabilities" in input_data and isinstance(
                input_data["vulnerabilities"], list
            ):
                logger.info("Processing Red Team repository results")
                return process_repository_results(input_data, motivation_data)

            # If input is a single vulnerability
            elif "description" in input_data and "vulnerability_type" in input_data:
                logger.info("Processing single vulnerability")

                # Extract motivation analysis if available
                motivation_analysis = None
                if (
                    isinstance(motivation_data, dict)
                    and "primary_motivation" in motivation_data
                ):
                    motivation_analysis = motivation_data

                fix = generate_vulnerability_fix(input_data, motivation_analysis)
                return {
                    "analysis_timestamp": time.time(),
                    "vulnerabilities_remediated": 1,
                    "individual_remediations": [
                        {
                            "vulnerability": {
                                "description": input_data.get("description", ""),
                                "type": input_data.get("vulnerability_type", ""),
                                "severity": input_data.get("severity", ""),
                            },
                            "remediation": fix,
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

            # Extract motivation analyses if available
            motivation_analyses = None
            if (
                isinstance(motivation_data, dict)
                and "individual_analyses" in motivation_data
            ):
                motivation_analyses = motivation_data.get("individual_analyses", [])
            elif isinstance(motivation_data, list):
                motivation_analyses = motivation_data

            return generate_fixes_for_vulnerability_set(input_data, motivation_analyses)

        # Invalid input
        logger.error("Invalid input format for Blue Team Agent")
        return {
            "error": "Invalid input format",
            "message": "Expected a Red Team result dictionary or a list of vulnerabilities",
            "analysis_timestamp": time.time(),
        }

    except Exception as e:
        logger.error(f"Error in blue_team_agent_function: {str(e)}")
        return {
            "error": str(e),
            "analysis_timestamp": time.time(),
            "message": "An error occurred during remediation generation",
        }


def main():
    """
    Test function to demonstrate using the Blue Team Agent.
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

    # Sample motivation analysis
    test_motivation = {
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

    # Generate fix for the vulnerability with motivation context
    result = generate_vulnerability_fix(test_vulnerability, test_motivation)
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

    # Sample motivation analyses
    test_motivation_analyses = [
        {
            "vulnerability": {
                "description": "SQL Injection vulnerability due to direct concatenation of user input"
            },
            "motivation_analysis": test_motivation,
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
    ]

    # Generate fixes for the set of vulnerabilities with motivation context
    set_result = generate_fixes_for_vulnerability_set(
        test_vulnerabilities, test_motivation_analyses
    )
    print(json.dumps(set_result, indent=2))


if __name__ == "__main__":
    main()
