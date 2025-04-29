"""
Red Team Agent for Agent Purple

This module implements the Red Team Agent, which scans code repositories for vulnerabilities
in AI-enabled systems using the OpenAI API and maps them to MITRE ATT&CK and ATLAS frameworks.
"""

import os
import json
import logging
import hashlib
from typing import Dict, List, Any, Optional
import functools
import time

from openai import OpenAI
from dotenv import load_dotenv

# Import utility modules
from utils.data_fetcher import fetch_mitre_attack_data, fetch_mitre_atlas_data

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

# Severity levels with descriptions
SEVERITY_LEVELS = {
    "CRITICAL": "Severe vulnerability that can lead to system compromise with minimal effort",
    "HIGH": "Significant vulnerability that poses substantial risk to the AI system",
    "MEDIUM": "Moderate vulnerability that could be exploited under certain conditions",
    "LOW": "Minor vulnerability with limited impact or exploitation potential",
    "INFO": "Informational finding with minimal security impact",
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
def analyze_code_with_openai(code_snippet: str, file_path: str) -> Dict[str, Any]:
    """
    Use OpenAI API to analyze a code snippet for vulnerabilities.

    Args:
        code_snippet: String containing the code to analyze
        file_path: Path to the file being analyzed

    Returns:
        Dictionary containing identified vulnerabilities
    """
    try:
        logger.info(f"Analyzing file: {file_path}")

        # Construct prompt for vulnerability analysis
        prompt = f"""
        Analyze the following code snippet for security vulnerabilities, particularly focusing on AI-enabled systems.
        For each vulnerability found, provide:
        1. A brief description
        2. The severity level (CRITICAL, HIGH, MEDIUM, LOW, INFO)
        3. The line numbers where the vulnerability exists
        4. The type of vulnerability
        5. Possible exploitation scenarios
        6. How it relates to AI systems if applicable
        
        Code to analyze (from {file_path}):
        ```
        {code_snippet}
        ```
        
        Format your response as valid JSON with the following structure:
        {{
            "vulnerabilities": [
                {{
                    "description": "Description of the vulnerability",
                    "severity": "SEVERITY_LEVEL",
                    "line_numbers": [line_numbers],
                    "vulnerability_type": "Type of vulnerability",
                    "exploitation_scenarios": "Description of how this could be exploited",
                    "ai_impact": "Description of how this vulnerability impacts AI systems"
                }}
            ]
        }}
        
        If no vulnerabilities are found, return an empty array for "vulnerabilities".
        """

        # Call OpenAI API using GPT-4o model for better analysis
        response = client.chat.completions.create(
            model="gpt-4o",  # Updated from gpt-4 to gpt-4o for improved analysis
            messages=[
                {
                    "role": "system",
                    "content": "You are a security expert focused on identifying vulnerabilities in AI systems.",
                },
                {"role": "user", "content": prompt},
            ],
            temperature=0.2,  # Lower temperature for more deterministic responses
            max_tokens=2000,
        )

        # Extract and parse the response
        result_text = response.choices[0].message.content

        # Extract JSON from the response (in case there's any extra text)
        json_start = result_text.find("{")
        json_end = result_text.rfind("}") + 1
        if json_start >= 0 and json_end > json_start:
            json_str = result_text[json_start:json_end]
            result = json.loads(json_str)
        else:
            # Fallback if no JSON is found
            logger.warning("No valid JSON found in API response")
            result = {"vulnerabilities": []}

        return result

    except Exception as e:
        logger.error(f"Error analyzing code with OpenAI: {str(e)}")
        return {"vulnerabilities": [], "error": str(e)}


def map_vulnerability_to_frameworks(vulnerability: Dict[str, Any]) -> Dict[str, Any]:
    """
    Maps an identified vulnerability to MITRE ATT&CK and ATLAS frameworks.

    Args:
        vulnerability: Dictionary containing vulnerability information

    Returns:
        Updated vulnerability dictionary with framework mappings
    """
    try:
        # Get framework data
        attack_data = fetch_mitre_attack_data()
        atlas_data = fetch_mitre_atlas_data()

        # Create a prompt for mapping to frameworks
        vuln_description = f"{vulnerability['description']} of type {vulnerability['vulnerability_type']} with impact: {vulnerability['ai_impact']}"
        prompt = f"""
        Map the following vulnerability to MITRE ATT&CK and MITRE ATLAS frameworks:
        
        Vulnerability: {vuln_description}
        
        For each framework, provide:
        1. Relevant tactics (IDs and names)
        2. Relevant techniques (IDs and names)
        3. Brief explanation of why this mapping is appropriate
        
        Format your response as valid JSON with the following structure:
        {{
            "mitre_attack": {{
                "tactics": [
                    {{ "id": "TA0001", "name": "Initial Access" }}
                ],
                "techniques": [
                    {{ "id": "T1190", "name": "Exploit Public-Facing Application" }}
                ],
                "explanation": "This vulnerability allows for..."
            }},
            "mitre_atlas": {{
                "tactics": [
                    {{ "id": "TA0001", "name": "ML Model Access" }}
                ],
                "techniques": [
                    {{ "id": "AML.T0001", "name": "Data Poisoning" }}
                ],
                "explanation": "This vulnerability could enable..."
            }}
        }}
        """

        # Call OpenAI API for mapping using GPT-4o
        response = client.chat.completions.create(
            model="gpt-4o",  # Updated to GPT-4o for improved framework mapping
            messages=[
                {
                    "role": "system",
                    "content": "You are an expert in security frameworks like MITRE ATT&CK and ATLAS.",
                },
                {"role": "user", "content": prompt},
            ],
            temperature=0.2,
            max_tokens=1000,
        )

        # Extract and parse the response
        result_text = response.choices[0].message.content

        # Extract JSON from the response
        json_start = result_text.find("{")
        json_end = result_text.rfind("}") + 1
        if json_start >= 0 and json_end > json_start:
            json_str = result_text[json_start:json_end]
            mapping_result = json.loads(json_str)
        else:
            # Fallback if no JSON is found
            logger.warning("No valid JSON found in mapping response")
            mapping_result = {
                "mitre_attack": {
                    "tactics": [],
                    "techniques": [],
                    "explanation": "Mapping failed",
                },
                "mitre_atlas": {
                    "tactics": [],
                    "techniques": [],
                    "explanation": "Mapping failed",
                },
            }

        # Update the vulnerability with framework mappings
        vulnerability["framework_mappings"] = mapping_result

        return vulnerability

    except Exception as e:
        logger.error(f"Error mapping vulnerability to frameworks: {str(e)}")
        vulnerability["framework_mappings"] = {
            "mitre_attack": {
                "tactics": [],
                "techniques": [],
                "explanation": f"Error: {str(e)}",
            },
            "mitre_atlas": {
                "tactics": [],
                "techniques": [],
                "explanation": f"Error: {str(e)}",
            },
        }
        return vulnerability


def analyze_file(file_path: str, file_content: str) -> Dict[str, Any]:
    """
    Analyzes a file for vulnerabilities and maps them to frameworks.

    Args:
        file_path: Path to the file being analyzed
        file_content: Content of the file to analyze

    Returns:
        Dictionary containing analysis results including vulnerabilities and mappings
    """
    start_time = time.time()
    logger.info(f"Starting analysis of {file_path}")

    # Step 1: Analyze code for vulnerabilities
    analysis_result = analyze_code_with_openai(file_content, file_path)

    # Step 2: Map each vulnerability to frameworks
    for vuln in analysis_result.get("vulnerabilities", []):
        vuln = map_vulnerability_to_frameworks(vuln)

        # Add additional metadata
        vuln["file_path"] = file_path
        vuln["severity_description"] = SEVERITY_LEVELS.get(
            vuln.get("severity", "INFO"), ""
        )

    elapsed_time = time.time() - start_time
    logger.info(f"Completed analysis of {file_path} in {elapsed_time:.2f} seconds")

    return {
        "file_path": file_path,
        "analysis_timestamp": time.time(),
        "analysis_duration_seconds": elapsed_time,
        "vulnerabilities": analysis_result.get("vulnerabilities", []),
        "vulnerability_count": len(analysis_result.get("vulnerabilities", [])),
        "error": analysis_result.get("error", None),
    }


def analyze_repository(repository_files: List[Dict[str, str]]) -> Dict[str, Any]:
    """
    Analyzes all files in a repository for vulnerabilities.

    Args:
        repository_files: List of dictionaries with file paths and contents

    Returns:
        Dictionary containing analysis results for the entire repository
    """
    logger.info(f"Starting repository analysis with {len(repository_files)} files")
    start_time = time.time()

    # Analyze each file
    file_results = []
    for file_info in repository_files:
        file_path = file_info.get("file_path", "")
        file_content = file_info.get("content", "")

        # Skip empty files or non-code files
        if not file_content or not should_analyze_file(file_path):
            logger.info(f"Skipping {file_path} (empty or non-code file)")
            continue

        # Analyze the file
        result = analyze_file(file_path, file_content)
        file_results.append(result)

    # Aggregate results
    all_vulnerabilities = []
    for result in file_results:
        all_vulnerabilities.extend(result.get("vulnerabilities", []))

    # Sort vulnerabilities by severity
    severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
    sorted_vulnerabilities = sorted(
        all_vulnerabilities,
        key=lambda v: severity_order.get(v.get("severity", "INFO"), 999),
    )

    elapsed_time = time.time() - start_time
    logger.info(f"Completed repository analysis in {elapsed_time:.2f} seconds")

    return {
        "analysis_timestamp": time.time(),
        "analysis_duration_seconds": elapsed_time,
        "total_files_analyzed": len(file_results),
        "total_vulnerabilities": len(all_vulnerabilities),
        "vulnerability_summary": {
            "CRITICAL": sum(
                1 for v in all_vulnerabilities if v.get("severity") == "CRITICAL"
            ),
            "HIGH": sum(1 for v in all_vulnerabilities if v.get("severity") == "HIGH"),
            "MEDIUM": sum(
                1 for v in all_vulnerabilities if v.get("severity") == "MEDIUM"
            ),
            "LOW": sum(1 for v in all_vulnerabilities if v.get("severity") == "LOW"),
            "INFO": sum(1 for v in all_vulnerabilities if v.get("severity") == "INFO"),
        },
        "vulnerabilities": sorted_vulnerabilities,
        "file_results": file_results,
    }


def should_analyze_file(file_path: str) -> bool:
    """
    Determines if a file should be analyzed based on its extension and path.

    Args:
        file_path: Path to the file

    Returns:
        Boolean indicating whether the file should be analyzed
    """
    # Skip common non-code or binary files
    skip_extensions = {
        ".jpg",
        ".jpeg",
        ".png",
        ".gif",
        ".bmp",
        ".svg",
        ".mp3",
        ".wav",
        ".mp4",
        ".avi",
        ".mov",
        ".pdf",
        ".doc",
        ".docx",
        ".xls",
        ".xlsx",
        ".ppt",
        ".pptx",
        ".zip",
        ".tar",
        ".gz",
        ".rar",
        ".pyc",
        ".class",
        ".o",
        ".so",
        ".dll",
        ".DS_Store",
        ".gitignore",
    }

    # Skip common directories
    skip_directories = {
        "node_modules",
        "__pycache__",
        ".git",
        "venv",
        "env",
        "dist",
        "build",
        "target",
        "bin",
        "obj",
    }

    # Check file extension
    _, ext = os.path.splitext(file_path.lower())
    if ext in skip_extensions:
        return False

    # Check if file is in a directory to be skipped
    path_parts = file_path.split(os.path.sep)
    for part in path_parts:
        if part in skip_directories:
            return False

    # Also check for Unix-style paths (in case of mixed path separators)
    if "/" in file_path:
        unix_path_parts = file_path.split("/")
        for part in unix_path_parts:
            if part in skip_directories:
                return False

    return True


def main():
    """
    Test function to demonstrate using the Red Team Agent.
    """
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

    result = analyze_file("test_file.py", test_code)
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
