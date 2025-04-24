#!/usr/bin/env python
"""
Test script for GitHub Client

This script tests the functionality of the GitHub client to ensure it meets
the requirements of the Agent Purple project.
"""

import logging
import os
import sys
from pathlib import Path

# Add parent directory to path to import utils module
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
from utils.github_client import GitHubClient, GitHubError, enable_debug_logging

# Setup logging
logging.basicConfig(
    level=logging.INFO, format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger("test_github_client")


def test_git_installed():
    """Test if Git is installed on the system."""
    logger.info("Testing if Git is installed...")
    try:
        import subprocess

        result = subprocess.run(["git", "--version"], capture_output=True, text=True)
        if result.returncode != 0:
            logger.error(
                "Git is not installed or not in PATH. Please install Git and try again."
            )
            logger.error(f"Error: {result.stderr}")
            return False
        logger.info(f"Git is installed: {result.stdout.strip()}")
        return True
    except Exception as e:
        logger.error(f"Failed to check Git installation: {e}")
        return False


def test_github_client():
    """Test the GitHub client functionality."""
    logger.info("Testing GitHub client...")

    # Test repository URL - using a small, public repo
    test_repo_url = "https://github.com/octocat/Hello-World"

    try:
        # Enable debug logging for more detailed output
        enable_debug_logging()

        logger.info(f"Initializing GitHubClient...")
        with GitHubClient() as client:
            logger.info("Client initialized successfully.")

            # Test cloning repository
            logger.info(f"Cloning repository: {test_repo_url}")
            repo_path = client.clone_repository(test_repo_url)
            logger.info(f"Repository cloned successfully to: {repo_path}")

            # Test listing files
            logger.info("Listing files in repository...")
            files = client.list_files()
            logger.info(f"Found {len(files)} files in the repository.")

            # Display some files (limited to 10)
            if files:
                logger.info("Sample files:")
                for file in files[:10]:
                    logger.info(f"  - {file}")

                # Test reading a file
                sample_file = files[0]
                logger.info(f"Reading file content: {sample_file}")
                content = client.read_file(sample_file)
                content_preview = (
                    content[:100] + "..." if len(content) > 100 else content
                )
                logger.info(f"File content preview: {content_preview}")

                # Test searching code
                search_term = "Hello"
                logger.info(f"Searching for code containing: {search_term}")
                search_results = client.search_code(search_term)
                logger.info(
                    f"Found {len(search_results.get('items', []))} files containing '{search_term}'"
                )

                # Display search results
                if search_results.get("items"):
                    logger.info("Search results:")
                    for item in search_results["items"][:5]:
                        logger.info(f"  - {item.get('path')}")

            logger.info("GitHub client tests completed successfully.")
            return True
    except GitHubError as e:
        logger.error(f"GitHub error: {e}")
        return False
    except Exception as e:
        logger.error(f"Unexpected error: {e}")
        return False


def run_tests():
    """Run all tests for the GitHub client."""
    logger.info("Starting GitHub client tests...")

    # Check if Git is installed
    if not test_git_installed():
        logger.error("Git check failed. Cannot proceed with GitHub client tests.")
        return False

    # Test the GitHub client
    if not test_github_client():
        logger.error("GitHub client tests failed.")
        return False

    logger.info("All tests completed successfully!")
    return True


if __name__ == "__main__":
    success = run_tests()
    sys.exit(0 if success else 1)
