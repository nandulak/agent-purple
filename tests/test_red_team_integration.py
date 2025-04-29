"""
Integration test for the Red Team Agent with a real AI code repository.

This test will clone a small AI code repository with intentional vulnerabilities 
and run the Red Team Agent on it to verify detection capabilities using GPT-4o.
"""

import os
import sys
import json
import logging
import tempfile
import subprocess
from pathlib import Path
from dotenv import load_dotenv

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Add the parent directory to the path so we can import our modules
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

# Import Red Team Agent functionality
from agents.red_team_agent import analyze_file

# Repository with AI code that might contain vulnerabilities
TEST_REPO_URL = "https://github.com/tensorflow/models.git"
TEST_FILES = [
    "official/recommendation/ranking/train.py",
    "official/nlp/modeling/layers/transformer_encoder_block.py",
    "official/projects/token_dropping/train.py"
]


def clone_repository(repo_url, target_dir):
    """
    Clones a GitHub repository to the specified directory.
    
    Args:
        repo_url: URL of the repository to clone
        target_dir: Directory to clone the repository into
        
    Returns:
        bool: True if successful, False otherwise
    """
    try:
        logger.info(f"Cloning repository {repo_url} to {target_dir}")
        subprocess.run(
            ["git", "clone", "--depth", "1", repo_url, target_dir],
            check=True, 
            capture_output=True,
            text=True
        )
        return True
    except subprocess.CalledProcessError as e:
        logger.error(f"Failed to clone repository: {e.stderr}")
        return False
    except Exception as e:
        logger.error(f"Unexpected error cloning repository: {str(e)}")
        return False


def read_file_content(file_path):
    """
    Reads the content of a file.
    
    Args:
        file_path: Path to the file
        
    Returns:
        str: Content of the file or None if error
    """
    try:
        with open(file_path, "r", encoding="utf-8") as f:
            return f.read()
    except Exception as e:
        logger.error(f"Error reading file {file_path}: {str(e)}")
        return None


def run_integration_test():
    """
    Runs the integration test with a real AI code repository.
    """
    logger.info("Starting Red Team Agent integration test with real AI code repository")
    
    # Check if OpenAI API key is available
    if not os.getenv("OPENAI_API_KEY"):
        logger.error("OpenAI API key not found. Please set OPENAI_API_KEY environment variable.")
        return False
    
    # Create a temporary directory for the repository
    with tempfile.TemporaryDirectory() as temp_dir:
        # Clone the repository
        if not clone_repository(TEST_REPO_URL, temp_dir):
            logger.error("Failed to clone repository. Exiting test.")
            return False
        
        logger.info(f"Repository cloned successfully to {temp_dir}")
        
        results = []
        # Process each test file
        for file_name in TEST_FILES:
            file_path = os.path.join(temp_dir, file_name)
            if os.path.exists(file_path):
                logger.info(f"Analyzing file: {file_name}")
                
                file_content = read_file_content(file_path)
                if file_content:
                    # Use Red Team Agent to analyze the file
                    start_message = f"Starting analysis of {file_name} with Red Team Agent using GPT-4o model"
                    logger.info(f"{'-' * len(start_message)}")
                    logger.info(start_message)
                    logger.info(f"{'-' * len(start_message)}")
                    
                    result = analyze_file(file_path, file_content)
                    results.append(result)
                    
                    # Log the results
                    logger.info(f"Analysis completed for {file_name}")
                    logger.info(f"Found {result['vulnerability_count']} vulnerabilities")
                    
                    # Print summary of detected vulnerabilities
                    for i, vuln in enumerate(result.get('vulnerabilities', [])):
                        logger.info(f"Vulnerability {i+1}:")
                        logger.info(f"  Description: {vuln.get('description', 'N/A')}")
                        logger.info(f"  Severity: {vuln.get('severity', 'N/A')}")
                        logger.info(f"  Line numbers: {vuln.get('line_numbers', [])}")
                        logger.info(f"  Type: {vuln.get('vulnerability_type', 'N/A')}")
                        
                        # Show MITRE ATT&CK mapping if available
                        if 'framework_mappings' in vuln:
                            attack = vuln['framework_mappings'].get('mitre_attack', {})
                            atlas = vuln['framework_mappings'].get('mitre_atlas', {})
                            
                            # Log ATT&CK tactics and techniques
                            if attack.get('tactics'):
                                tactics = [f"{t.get('id', 'N/A')} ({t.get('name', 'N/A')})" for t in attack.get('tactics', [])]
                                logger.info(f"  ATT&CK Tactics: {', '.join(tactics)}")
                            
                            if attack.get('techniques'):
                                techniques = [f"{t.get('id', 'N/A')} ({t.get('name', 'N/A')})" for t in attack.get('techniques', [])]
                                logger.info(f"  ATT&CK Techniques: {', '.join(techniques)}")
                            
                            # Log ATLAS tactics and techniques
                            if atlas.get('tactics'):
                                tactics = [f"{t.get('id', 'N/A')} ({t.get('name', 'N/A')})" for t in atlas.get('tactics', [])]
                                logger.info(f"  ATLAS Tactics: {', '.join(tactics)}")
                            
                            if atlas.get('techniques'):
                                techniques = [f"{t.get('id', 'N/A')} ({t.get('name', 'N/A')})" for t in atlas.get('techniques', [])]
                                logger.info(f"  ATLAS Techniques: {', '.join(techniques)}")
                        
                        logger.info("")  # Empty line for readability
            else:
                logger.warning(f"File not found: {file_path}")
        
        # Save results to JSON file
        if results:
            output_dir = Path("test_results")
            output_dir.mkdir(exist_ok=True)
            output_file = output_dir / "red_team_integration_test_results.json"
            
            with open(output_file, "w", encoding="utf-8") as f:
                json.dump(results, f, indent=2, default=str)
            
            logger.info(f"Results saved to {output_file}")
            return True
        
        logger.warning("No results were generated from the test")
        return False


if __name__ == "__main__":
    # Load environment variables
    load_dotenv()
    
    # Set the environment variable for integration tests
    os.environ["RUN_INTEGRATION_TESTS"] = "1"
    
    # Run the integration test
    success = run_integration_test()
    
    if success:
        logger.info("Integration test completed successfully")
        sys.exit(0)
    else:
        logger.error("Integration test failed")
        sys.exit(1)