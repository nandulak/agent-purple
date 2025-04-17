#!/usr/bin/env python
"""
GitHub MCP Client Module for Agent Purple

This module provides functionality to interact with GitHub repositories via the GitHub MCP Server.
It enables cloning repositories, listing files, reading file contents, and other operations.
"""

import json
import logging
import os
import re
import subprocess
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple, Union

import requests
from dotenv import load_dotenv

# Setup logging
logging.basicConfig(
    level=logging.INFO, format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger("github_mcp_client")


class MCPServerError(Exception):
    """Exception raised for errors in MCP server communication."""

    pass


class GitHubMCPClient:
    """
    Client for interacting with GitHub repositories through the GitHub MCP Server.

    This client provides an interface to:
    - Clone repositories
    - List files in repositories
    - Read file contents
    - And other GitHub operations

    It uses the Model Context Protocol (MCP) server which provides a standardized
    interface between AI models and GitHub's APIs.
    """

    def __init__(
        self,
        server_url: str = None,
        token: str = None,
        docker_image: str = "ghcr.io/github/github-mcp-server",
    ):
        """
        Initialize the GitHub MCP client.

        Args:
            server_url: URL of an existing MCP server if not using Docker
            token: GitHub Personal Access Token (if not provided, it will be loaded from .env)
            docker_image: The Docker image name for the GitHub MCP server
        """
        load_dotenv()  # Load environment variables from .env file

        self.docker_image = docker_image
        self.server_url = server_url
        self.token = (
            token
            or os.getenv("GITHUB_PERSONAL_ACCESS_TOKEN")
            or os.getenv("GITHUB_TOKEN")
        )

        if not self.token:
            raise ValueError(
                "GitHub Personal Access Token not found. Provide it as an argument or set in .env file."
            )

        self.docker_server_process = None
        self.temp_dir = None
        self.cloned_repo_path = None
        self.repo_owner = None
        self.repo_name = None
        self.request_id = 1  # For JSON-RPC request IDs

        logger.info("GitHub MCP Client initialized")

    def __enter__(self):
        """Context manager entry point."""
        if not self.server_url:
            self._start_mcp_server()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit point - clean up resources."""
        self._stop_mcp_server()
        if self.temp_dir:
            logger.info(f"Cleaning up temporary directory: {self.temp_dir}")
            try:
                # Keep the directory for now as it might contain the cloned repo
                # In a real-world scenario, consider adding an option to remove it
                pass
            except Exception as e:
                logger.warning(f"Failed to clean up temporary directory: {e}")

    def _start_mcp_server(self):
        """Start the GitHub MCP server using Docker."""
        logger.info("Starting GitHub MCP server in Docker")
        try:
            self.temp_dir = tempfile.mkdtemp(prefix="github_mcp_")
            logger.info(f"Created temporary directory: {self.temp_dir}")

            # Check if Docker is running
            try:
                subprocess.run(["docker", "info"], check=True, capture_output=True)
            except subprocess.CalledProcessError:
                raise MCPServerError(
                    "Docker is not running. Please start Docker and try again."
                )

            # Use docker-compose and a custom configuration to start the MCP server
            container_name = f"github-mcp-server-{os.path.basename(self.temp_dir)}"

            # Run MCP server in Docker container in background mode
            logger.info("Running MCP server in Docker container")

            cmd = [
                "docker",
                "run",
                "-i",
                "--name",
                container_name,
                "-e",
                f"GITHUB_PERSONAL_ACCESS_TOKEN={self.token}",
                "--rm",
                self.docker_image,
            ]

            logger.debug(f"Docker command: {' '.join(cmd)}")

            self.docker_server_process = subprocess.Popen(
                cmd,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,  # Use text mode instead of binary
                bufsize=1,
            )

            # Wait a moment to ensure the server is ready
            time.sleep(2)

            # Check if the container started successfully
            try:
                container_check = subprocess.run(
                    [
                        "docker",
                        "ps",
                        "--filter",
                        f"name={container_name}",
                        "--format",
                        "{{.Names}}",
                    ],
                    capture_output=True,
                    text=True,
                    check=True,
                )
                if container_name not in container_check.stdout:
                    stderr_output = self.docker_server_process.stderr.read(1024)
                    raise MCPServerError(
                        f"Failed to start MCP server container. Error: {stderr_output}"
                    )
            except subprocess.CalledProcessError as e:
                raise MCPServerError(f"Error checking Docker container status: {e}")

            logger.info("GitHub MCP server started in Docker")

        except Exception as e:
            logger.error(f"Failed to start MCP server: {e}")
            if self.temp_dir and Path(self.temp_dir).exists():
                os.rmdir(self.temp_dir)
            raise MCPServerError(f"Failed to start MCP server: {e}")

    def _stop_mcp_server(self):
        """Stop the GitHub MCP server Docker container."""
        if self.docker_server_process:
            logger.info("Stopping GitHub MCP server Docker container")
            try:
                self.docker_server_process.terminate()
                self.docker_server_process.wait(timeout=5)
                self.docker_server_process = None
            except Exception as e:
                logger.error(f"Error stopping Docker container: {e}")
                # Try to force kill the container if termination failed
                try:
                    self.docker_server_process.kill()
                except Exception:
                    pass

    def _send_mcp_request(
        self, tool_name: str, params: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Send a request to the MCP server.

        Args:
            tool_name: Name of the MCP tool to call
            params: Parameters to pass to the tool

        Returns:
            MCP server response as a dictionary
        """
        try:
            # Get the next request ID
            request_id = self.request_id
            self.request_id += 1

            # MCP protocol message format - tools are directly used as method names
            message = {
                "jsonrpc": "2.0",
                "id": request_id,
                "method": tool_name,
                "params": params,
            }

            if self.server_url:
                # HTTP transport
                logger.debug(f"Sending HTTP request: {json.dumps(message)}")
                response = requests.post(
                    self.server_url,
                    json=message,
                    headers={"Authorization": f"Bearer {self.token}"},
                )
                response.raise_for_status()
                result = response.json()
                logger.debug(f"Received HTTP response: {json.dumps(result)}")
                return result.get("result", {})
            else:
                # Stdio transport
                message_str = json.dumps(message) + "\n"
                logger.debug(f"Sending message: {message_str.strip()}")

                if (
                    not self.docker_server_process
                    or self.docker_server_process.poll() is not None
                ):
                    raise MCPServerError("Docker process is not running")

                self.docker_server_process.stdin.write(message_str)
                self.docker_server_process.stdin.flush()

                # Read response
                response_str = self.docker_server_process.stdout.readline()
                logger.debug(f"Received response: {response_str.strip()}")

                if not response_str:
                    stderr_output = self.docker_server_process.stderr.readline()
                    raise MCPServerError(
                        f"Empty response from MCP server. Error: {stderr_output}"
                    )

                try:
                    response = json.loads(response_str)
                except json.JSONDecodeError:
                    raise MCPServerError(
                        f"Invalid JSON response from MCP server: {response_str}"
                    )

                if "error" in response:
                    error = response["error"]
                    raise MCPServerError(
                        f"MCP server error: {error.get('message', 'Unknown error')}"
                    )

                return response.get("result", {})

        except MCPServerError:
            raise  # Re-raise MCP server errors directly
        except Exception as e:
            logger.error(f"Error during MCP request {tool_name}: {e}")
            raise MCPServerError(f"Failed to execute MCP request: {e}")

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
            self.temp_dir = tempfile.mkdtemp(prefix="github_mcp_")

        self.cloned_repo_path = os.path.join(self.temp_dir, self.repo_name)
        os.makedirs(self.cloned_repo_path, exist_ok=True)

        logger.info(f"Repository will be cloned to {self.cloned_repo_path}")

        # For testing purposes, we'll use the git CLI directly instead of MCP
        # This is more reliable and allows us to validate the basic functionality
        try:
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
            raise MCPServerError(f"Failed to clone repository: {e.stderr}")
        except Exception as e:
            logger.error(f"Error cloning repository: {e}")
            raise MCPServerError(f"Failed to clone repository: {e}")

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

        target_path = (
            os.path.join(self.cloned_repo_path, path) if path else self.cloned_repo_path
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

        full_path = os.path.join(self.cloned_repo_path, file_path)

        if not os.path.isfile(full_path):
            raise FileNotFoundError(f"File not found: {file_path}")

        try:
            with open(full_path, "r", encoding="utf-8") as f:
                return f.read()
        except Exception as e:
            logger.error(f"Error reading file {file_path}: {e}")
            raise MCPServerError(f"Failed to read file: {e}")

    def search_code(self, query: str) -> Dict:
        """
        Search for code in the repository.

        Args:
            query: Search query string

        Returns:
            Search results as a dictionary
        """
        logger.info(f"Searching code with query: {query}")

        if not self.repo_owner or not self.repo_name:
            raise ValueError(
                "Repository owner and name not set. Call clone_repository first."
            )

        # For now, search locally in the cloned repository using grep
        try:
            grep_cmd = [
                "grep",
                "-r",
                "-l",
                "--include=*.*",
                query,
                self.cloned_repo_path,
            ]
            result = subprocess.run(
                grep_cmd,
                capture_output=True,
                text=True,
                check=False,  # Don't throw an error if grep doesn't find anything
            )

            files = []
            if result.stdout:
                for line in result.stdout.splitlines():
                    rel_path = os.path.relpath(line, self.cloned_repo_path)
                    files.append(rel_path)

            return {"items": [{"path": file} for file in files]}

        except subprocess.CalledProcessError as e:
            if e.returncode == 1:  # grep returns 1 when it doesn't find anything
                return {"items": []}
            logger.error(f"Error searching code: {e}")
            raise MCPServerError(f"Failed to search code: {e}")
        except Exception as e:
            logger.error(f"Error searching code: {e}")
            raise MCPServerError(f"Failed to search code: {e}")

    def get_file_from_github(self, path: str, ref: str = None) -> str:
        """
        Get file content directly from GitHub without relying on local clone.

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

        # For now, if we have a local clone, use that
        if self.cloned_repo_path:
            return self.read_file(path)

        # Fallback to GitHub API via requests if MCP isn't working
        try:
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
                raise MCPServerError(f"Failed to get file content: {content}")
        except Exception as e:
            logger.error(f"Error getting file from GitHub: {e}")
            raise MCPServerError(f"Failed to get file from GitHub: {e}")

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

        params = {
            "owner": self.repo_owner,
            "repo": self.repo_name,
            "title": title,
            "body": body,
        }

        if labels:
            params["labels"] = labels

        try:
            return self._send_mcp_request("create_issue", params)
        except Exception as e:
            logger.error(f"Error creating issue: {e}")
            raise MCPServerError(f"Failed to create issue: {e}")

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

        params = {
            "owner": self.repo_owner,
            "repo": self.repo_name,
            "title": title,
            "body": body,
            "head": head,
            "base": base,
        }

        try:
            return self._send_mcp_request("create_pull_request", params)
        except Exception as e:
            logger.error(f"Error creating pull request: {e}")
            raise MCPServerError(f"Failed to create pull request: {e}")


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

    # Example usage of the GitHub MCP client
    try:
        with GitHubMCPClient() as client:
            repo_path = client.clone_repository(
                "https://github.com/ModelContractProtocol/python-sdk"
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
