#!/usr/bin/env python
"""
GitHub Client Module for Agent Purple

This module provides functionality to interact with GitHub repositories via direct Git operations.
It enables cloning repositories, listing files, reading file contents, and other operations.

Note: Future enhancement will include integration with the GitHub MCP Server.
"""

import logging
import os
import re
import subprocess
import tempfile
from pathlib import Path
from typing import Any, Dict, List, Optional, Union

import requests
from dotenv import load_dotenv

# Setup logging
logging.basicConfig(
    level=logging.INFO, format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger("github_client")


class GitHubError(Exception):
    """Exception raised for errors in GitHub operations."""

    pass


class GitHubClient:
    """
    Client for interacting with GitHub repositories through direct Git operations.

    This client provides an interface to:
    - Clone repositories
    - List files in repositories
    - Read file contents
    - Search code
    - Create issues and PRs (via GitHub API)

    TODO: Future enhancement will include integration with the GitHub MCP Server
    which provides a standardized interface between AI models and GitHub's APIs.
    """

    def __init__(self, token: str = None):
        """
        Initialize the GitHub client.

        Args:
            token: GitHub Personal Access Token (if not provided, it will be loaded from .env)
        """
        load_dotenv()  # Load environment variables from .env file

        self.token = (
            token
            or os.getenv("GITHUB_PERSONAL_ACCESS_TOKEN")
            or os.getenv("GITHUB_TOKEN")
        )

        if not self.token:
            raise ValueError(
                "GitHub Personal Access Token not found. Provide it as an argument or set in .env file."
            )

        self.temp_dir = None
        self.cloned_repo_path = None
        self.repo_owner = None
        self.repo_name = None

        logger.info("GitHub Client initialized")

    def __enter__(self):
        """Context manager entry point."""
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit point - clean up resources."""
        if self.temp_dir:
            logger.info(f"Temporary directory remains at: {self.temp_dir}")
            logger.info("You may want to manually remove it when no longer needed.")

    def clone_repository(self, repo_url: str, branch: str = None) -> str:
        """
        Clone a GitHub repository.

        Args:
            repo_url: URL of the GitHub repository to clone
            branch: Optional branch name to check out

        Returns:
            Path to the cloned repository
        """
        # Validate and parse GitHub URL
        match = re.match(r"https?://github\.com/([^/]+)/([^/]+)", repo_url)
        if not match:
            raise ValueError(f"Invalid GitHub repository URL: {repo_url}")

        self.repo_owner = match.group(1)
        self.repo_name = match.group(2).rstrip(".git")

        logger.info(f"Cloning repository {self.repo_owner}/{self.repo_name}")

        # Create a path for the cloned repository
        if not self.temp_dir:
            self.temp_dir = tempfile.mkdtemp(prefix="github_")

        self.cloned_repo_path = os.path.join(self.temp_dir, self.repo_name)
        os.makedirs(self.cloned_repo_path, exist_ok=True)

        logger.info(f"Repository will be cloned to {self.cloned_repo_path}")

        try:
            # Direct Git clone
            cmd = ["git", "clone", repo_url]
            if branch:
                cmd.extend(["--branch", branch])
            cmd.append(self.cloned_repo_path)

            logger.info(f"Running: {' '.join(cmd)}")
            result = subprocess.run(cmd, check=True, capture_output=True, text=True)
            logger.info(f"Repository cloned successfully to {self.cloned_repo_path}")

            return self.cloned_repo_path

        except subprocess.CalledProcessError as e:
            logger.error(f"Git error: {e.stderr}")
            raise GitHubError(f"Failed to clone repository: {e.stderr}")
        except Exception as e:
            logger.error(f"Error cloning repository: {e}")
            raise GitHubError(f"Failed to clone repository: {e}")

    def list_files(self, path: str = "", recursive: bool = True) -> List[str]:
        """
        List files in the cloned repository.

        Args:
            path: Relative path within the repository
            recursive: Whether to list files recursively

        Returns:
            List of file paths
        """
        if not self.cloned_repo_path:
            raise ValueError("Repository not cloned yet. Call clone_repository first.")

        try:
            # Direct file listing using Python's os module
            target_path = (
                os.path.join(self.cloned_repo_path, path)
                if path
                else self.cloned_repo_path
            )

            if not os.path.exists(target_path):
                logger.error(f"Path does not exist: {target_path}")
                return []

            if recursive:
                file_list = []
                for root, _, files in os.walk(target_path):
                    for file in files:
                        full_path = os.path.join(root, file)
                        rel_path = os.path.relpath(full_path, self.cloned_repo_path)
                        file_list.append(rel_path)
                return file_list
            else:
                return [
                    f
                    for f in os.listdir(target_path)
                    if os.path.isfile(os.path.join(target_path, f))
                ]

        except Exception as e:
            logger.error(f"Error listing files: {e}")
            raise GitHubError(f"Failed to list files: {e}")

    def read_file(self, file_path: str) -> str:
        """
        Read file content from the cloned repository.

        Args:
            file_path: Path to the file, relative to repository root

        Returns:
            File content as a string
        """
        if not self.cloned_repo_path:
            raise ValueError("Repository not cloned yet. Call clone_repository first.")

        try:
            # Direct file reading using Python's open function
            full_path = os.path.join(self.cloned_repo_path, file_path)

            if not os.path.isfile(full_path):
                raise FileNotFoundError(f"File not found: {file_path}")

            with open(full_path, "r", encoding="utf-8", errors="ignore") as f:
                return f.read()

        except FileNotFoundError:
            raise  # Re-raise file not found errors
        except Exception as e:
            logger.error(f"Error reading file {file_path}: {e}")
            raise GitHubError(f"Failed to read file: {e}")

    def search_code(self, query: str) -> Dict:
        """
        Search for code in the repository.

        Args:
            query: Search query string

        Returns:
            Search results as a dictionary
        """
        logger.info(f"Searching code with query: {query}")

        if not self.cloned_repo_path:
            raise ValueError("Repository not cloned yet. Call clone_repository first.")

        try:
            # Direct code search using Python's file operations
            files = []
            for root, _, filenames in os.walk(self.cloned_repo_path):
                for filename in filenames:
                    # Skip binary files and git internal files
                    if ".git" in root:
                        continue

                    full_path = os.path.join(root, filename)
                    rel_path = os.path.relpath(full_path, self.cloned_repo_path)

                    try:
                        # Try to open the file as text
                        with open(
                            full_path, "r", encoding="utf-8", errors="ignore"
                        ) as f:
                            content = f.read()
                            if query.lower() in content.lower():
                                files.append(rel_path)
                    except Exception as e:
                        # Skip files that can't be read as text
                        logger.debug(f"Skipping file {rel_path}: {e}")
                        continue

            return {"items": [{"path": file} for file in files]}

        except Exception as e:
            logger.error(f"Error searching code: {e}")
            raise GitHubError(f"Failed to search code: {e}")

    def get_file_from_github(self, path: str, ref: str = None) -> str:
        """
        Get file content directly from GitHub API without relying on local clone.

        Args:
            path: Path to the file in the repository
            ref: Git reference (branch, tag, or commit)

        Returns:
            File content as a string
        """
        if not self.repo_owner or not self.repo_name:
            raise ValueError(
                "Repository owner and name not set. Call clone_repository first."
            )

        try:
            # For local clones, try to read the file directly
            if self.cloned_repo_path:
                try:
                    full_path = os.path.join(self.cloned_repo_path, path)
                    if os.path.isfile(full_path):
                        with open(
                            full_path, "r", encoding="utf-8", errors="ignore"
                        ) as f:
                            return f.read()
                except Exception as file_e:
                    logger.warning(
                        f"Failed to read local file: {file_e}. Trying GitHub API directly."
                    )

            # If local read fails or no local clone exists, use GitHub API
            api_url = f"https://api.github.com/repos/{self.repo_owner}/{self.repo_name}/contents/{path}"
            params = {}
            if ref:
                params["ref"] = ref

            headers = {"Authorization": f"token {self.token}"}

            response = requests.get(api_url, params=params, headers=headers)
            response.raise_for_status()

            content = response.json()
            if "content" in content:
                import base64

                return base64.b64decode(content["content"]).decode("utf-8")
            else:
                raise GitHubError(f"Failed to get file content: {content}")

        except Exception as e:
            logger.error(f"Error getting file from GitHub: {e}")
            raise GitHubError(f"Failed to get file from GitHub: {e}")

    def create_issue(self, title: str, body: str, labels: List[str] = None) -> Dict:
        """
        Create a new issue in the repository.

        Args:
            title: Issue title
            body: Issue body text
            labels: List of labels to apply

        Returns:
            Created issue data
        """
        if not self.repo_owner or not self.repo_name:
            raise ValueError(
                "Repository owner and name not set. Call clone_repository first."
            )

        try:
            # Direct GitHub API call to create an issue
            api_url = f"https://api.github.com/repos/{self.repo_owner}/{self.repo_name}/issues"

            headers = {
                "Authorization": f"token {self.token}",
                "Accept": "application/vnd.github.v3+json",
            }

            data = {
                "title": title,
                "body": body,
            }

            if labels:
                data["labels"] = labels

            response = requests.post(api_url, json=data, headers=headers)
            response.raise_for_status()

            return response.json()

        except Exception as e:
            logger.error(f"Error creating issue: {e}")
            raise GitHubError(f"Failed to create issue: {e}")

    def create_pull_request(
        self, title: str, body: str, head: str, base: str = "main"
    ) -> Dict:
        """
        Create a new pull request.

        Args:
            title: Pull request title
            body: Pull request description
            head: Branch containing changes
            base: Branch to merge into

        Returns:
            Created pull request data
        """
        if not self.repo_owner or not self.repo_name:
            raise ValueError(
                "Repository owner and name not set. Call clone_repository first."
            )

        try:
            # Direct GitHub API call to create a pull request
            api_url = (
                f"https://api.github.com/repos/{self.repo_owner}/{self.repo_name}/pulls"
            )

            headers = {
                "Authorization": f"token {self.token}",
                "Accept": "application/vnd.github.v3+json",
            }

            data = {"title": title, "body": body, "head": head, "base": base}

            response = requests.post(api_url, json=data, headers=headers)
            response.raise_for_status()

            return response.json()

        except Exception as e:
            logger.error(f"Error creating pull request: {e}")
            raise GitHubError(f"Failed to create pull request: {e}")


# Enable debug logging at module level for troubleshooting
def enable_debug_logging():
    """Enable debug level logging for troubleshooting."""
    logger.setLevel(logging.DEBUG)
    for handler in logger.handlers:
        handler.setLevel(logging.DEBUG)


# Example usage
if __name__ == "__main__":
    # Enable debug logging for interactive testing
    enable_debug_logging()

    # Example usage of the GitHub client
    try:
        with GitHubClient() as client:
            repo_path = client.clone_repository(
                "https://github.com/octocat/Hello-World"
            )
            files = client.list_files()
            print(f"Files in repository: {files}")

            # Read a specific file
            if files:
                content = client.read_file(files[0])
                print(f"Content of {files[0]}:")
                print(content[:200] + "..." if len(content) > 200 else content)

    except Exception as e:
        print(f"Error: {e}")
