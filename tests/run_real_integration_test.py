"""
Run real integration tests for Agent Purple.

This script runs the full Agent Purple workflow with actual API calls:
1. Red Team Agent analyzes code for vulnerabilities
2. Motivation Analysis Agent analyzes developer motivations
3. Blue Team Agent suggests remediation strategies

Results are saved to the test_results directory.
"""

import os
import json
import time
from pathlib import Path

# Import the agents
from agents.red_team_agent import analyze_repository
from agents.motivation_analysis_agent import analyze_vulnerabilities_motivations
from agents.blue_team_agent import blue_team_agent_function

# Sample vulnerable code for testing
SAMPLE_CODE = """
def process_user_input(user_input):
    # This function processes user input for an AI model
    sql_query = "SELECT * FROM users WHERE username = '" + user_input + "'"
    return execute_query(sql_query)

def train_model(data_path):
    # Load training data
    training_data = load_data(data_path)
    
    # Initialize model
    model = AIModel()
    
    # Train the model with hardcoded API key
    api_key = "sk_test_AbCdEfGhIjKlMnOpQrStUvWxYz123456"
    model.train(training_data, api_key=api_key)
    
    return model

def process_user_data(data):
    # Process and store user data
    import pickle
    import base64
    
    # Decode and deserialize user data (insecure)
    decoded_data = base64.b64decode(data)
    user_object = pickle.loads(decoded_data)  # Vulnerable to pickle deserialization attacks
    
    return user_object
"""


def save_results(results, filename):
    """Save results to a JSON file in test_results directory."""
    result_dir = Path("test_results")
    result_dir.mkdir(exist_ok=True)

    file_path = result_dir / filename
    with open(file_path, "w") as f:
        json.dump(results, f, indent=2)

    print(f"Results saved to {file_path}")


def run_real_integration_test():
    """Run a full integration test with real API calls."""
    print("Starting real integration test with actual API calls...")

    # Create sample files with vulnerabilities
    sample_files = [
        {"file_path": "/app/sample_vulnerable_code.py", "content": SAMPLE_CODE}
    ]

    # Step 1: Red Team analysis
    print("\n1. Running Red Team analysis...")
    start_time = time.time()
    red_team_results = analyze_repository(sample_files)
    red_team_duration = time.time() - start_time
    print(f"Red Team analysis completed in {red_team_duration:.2f} seconds")

    # Check if vulnerabilities were found
    vulnerabilities = red_team_results.get("vulnerabilities", [])
    if not vulnerabilities:
        print("No vulnerabilities found by Red Team. Aborting test.")
        save_results(red_team_results, "real_integration_red_team_results.json")
        return

    print(f"Found {len(vulnerabilities)} vulnerabilities")

    # Step 2: Motivation Analysis
    print("\n2. Running Motivation Analysis...")
    start_time = time.time()
    motivation_results = analyze_vulnerabilities_motivations(vulnerabilities)
    motivation_duration = time.time() - start_time
    print(f"Motivation Analysis completed in {motivation_duration:.2f} seconds")

    # Step 3: Blue Team remediation
    print("\n3. Running Blue Team remediation...")
    start_time = time.time()
    blue_team_results = blue_team_agent_function(red_team_results, motivation_results)
    blue_team_duration = time.time() - start_time
    print(f"Blue Team remediation completed in {blue_team_duration:.2f} seconds")

    # Save individual results
    save_results(red_team_results, "real_integration_red_team_results.json")
    save_results(motivation_results, "real_integration_motivation_results.json")
    save_results(blue_team_results, "real_integration_blue_team_results.json")

    # Save combined results
    combined_results = {
        "test_description": "Real integration test with actual API calls",
        "analysis_timestamp": time.time(),
        "red_team_results": red_team_results,
        "motivation_results": motivation_results,
        "blue_team_results": blue_team_results,
        "execution_times": {
            "red_team_duration": red_team_duration,
            "motivation_analysis_duration": motivation_duration,
            "blue_team_duration": blue_team_duration,
            "total_duration": red_team_duration
            + motivation_duration
            + blue_team_duration,
        },
    }

    save_results(combined_results, "real_integration_combined_results.json")
    print("\nReal integration test completed successfully!")
    print(
        f"Total duration: {combined_results['execution_times']['total_duration']:.2f} seconds"
    )

    # Verify results
    print("\nSummary of results:")
    print(f"- Red Team found {len(vulnerabilities)} vulnerabilities")
    print(
        f"- Motivation Analysis analyzed {motivation_results.get('vulnerabilities_analyzed', 0)} vulnerabilities"
    )
    print(
        f"- Blue Team generated fixes for {blue_team_results.get('vulnerabilities_remediated', 0)} vulnerabilities"
    )

    # Verify that Blue Team processed all vulnerabilities
    assert blue_team_results.get("vulnerabilities_remediated") == len(
        vulnerabilities
    ), "Not all vulnerabilities were remediated"
    print("All vulnerabilities were successfully remediated")

    # Verify that Blue Team generated recommendations
    assert (
        "overall_recommendations" in blue_team_results
    ), "No overall recommendations generated"
    assert (
        "priority_actions" in blue_team_results["overall_recommendations"]
    ), "No priority actions in recommendations"
    print("Overall recommendations were generated successfully")

    print("\nIntegration test verified successfully!")

    return combined_results


if __name__ == "__main__":
    try:
        run_real_integration_test()
    except Exception as e:
        print(f"\nError during integration test: {str(e)}")
