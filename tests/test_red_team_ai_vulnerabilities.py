"""
Specialized tests for the Red Team Agent focused on AI-specific vulnerabilities.

This module contains tests that verify the Red Team Agent can correctly identify
vulnerabilities specific to AI and machine learning systems.
"""

import pytest
from unittest.mock import patch, MagicMock
import json

from agents.red_team_agent import analyze_code_with_openai, analyze_file


@pytest.fixture
def ai_model_with_vulnerabilities():
    """Sample AI model code with intentional vulnerabilities."""
    return """
    import tensorflow as tf
    import numpy as np
    import pickle
    from urllib.request import urlopen
    
    class VulnerableAIModel:
        def __init__(self, model_path=None):
            self.model = None
            if model_path:
                self.load_model(model_path)
        
        def load_model(self, model_path):
            # Vulnerable: Loading untrusted model using pickle
            if model_path.startswith('http'):
                with urlopen(model_path) as f:
                    self.model = pickle.load(f)
            else:
                with open(model_path, 'rb') as f:
                    self.model = pickle.load(f)
        
        def train(self, data, labels, epochs=10):
            # Vulnerable: No validation on training data
            X = np.array(data)
            y = np.array(labels)
            
            # Create a simple neural network
            model = tf.keras.Sequential([
                tf.keras.layers.Dense(128, activation='relu', input_shape=(X.shape[1],)),
                tf.keras.layers.Dropout(0.2),
                tf.keras.layers.Dense(64, activation='relu'),
                tf.keras.layers.Dense(1, activation='sigmoid')
            ])
            
            # No protection against model poisoning
            model.compile(optimizer='adam', loss='binary_crossentropy', metrics=['accuracy'])
            model.fit(X, y, epochs=epochs, verbose=0)
            self.model = model
        
        def predict(self, input_data, threshold=0.5):
            # Vulnerable: No input validation or sanitization
            # Could be vulnerable to adversarial examples
            if self.model is None:
                raise ValueError("Model not loaded or trained")
                
            predictions = self.model.predict(np.array([input_data]))
            return predictions[0] >= threshold
        
        def save_model(self, path):
            # Vulnerable: Saving with insecure permissions
            if isinstance(self.model, tf.keras.Model):
                self.model.save(path)
            else:
                with open(path, 'wb') as f:
                    pickle.dump(self.model, f)
        
        def evaluate_model(self, X_test, y_test):
            # Vulnerable: No protection against information leakage
            results = self.model.evaluate(X_test, y_test, verbose=0)
            print(f"Loss: {results[0]}, Accuracy: {results[1]}")
            
            # Detailed per-sample loss that could leak information
            individual_losses = []
            for i in range(len(X_test)):
                pred = self.model.predict(np.array([X_test[i]]), verbose=0)
                loss = float(abs(pred - y_test[i]))
                individual_losses.append((i, loss))
            
            # Sort by loss to identify most challenging samples
            return sorted(individual_losses, key=lambda x: x[1], reverse=True)
    """


@pytest.fixture
def mock_ai_vuln_response():
    """Mock OpenAI API response for AI-specific vulnerabilities."""
    return {
        "vulnerabilities": [
            {
                "description": "Insecure deserialization using pickle",
                "severity": "CRITICAL",
                "line_numbers": [13, 16],
                "vulnerability_type": "Insecure Deserialization",
                "exploitation_scenarios": "An attacker could craft a malicious pickle file to achieve remote code execution when loaded by the model",
                "ai_impact": "Could lead to complete compromise of the AI system and host environment",
            },
            {
                "description": "Lack of input validation in model prediction",
                "severity": "HIGH",
                "line_numbers": [37, 41],
                "vulnerability_type": "Input Validation",
                "exploitation_scenarios": "An attacker could craft adversarial examples to manipulate model predictions",
                "ai_impact": "Could cause the AI to make incorrect predictions or classifications",
            },
            {
                "description": "Information leakage in model evaluation",
                "severity": "MEDIUM",
                "line_numbers": [54, 60],
                "vulnerability_type": "Information Disclosure",
                "exploitation_scenarios": "An attacker could extract training data or model details through careful analysis of per-sample losses",
                "ai_impact": "Could enable model extraction attacks or membership inference attacks",
            },
            {
                "description": "No validation on training data",
                "severity": "HIGH",
                "line_numbers": [23, 24],
                "vulnerability_type": "Data Poisoning",
                "exploitation_scenarios": "An attacker could inject poisoned data into the training set",
                "ai_impact": "Could compromise the integrity of the model through targeted poisoning",
            },
        ]
    }


@pytest.fixture
def mock_ai_framework_mappings():
    """Mock framework mappings for AI vulnerabilities."""
    # Each vulnerability gets mapped to both ATT&CK and ATLAS
    return [
        # For insecure deserialization
        {
            "mitre_attack": {
                "tactics": [{"id": "TA0004", "name": "Privilege Escalation"}],
                "techniques": [
                    {"id": "T1203", "name": "Exploitation for Client Execution"}
                ],
                "explanation": "Insecure deserialization allows attackers to execute arbitrary code",
            },
            "mitre_atlas": {
                "tactics": [{"id": "TA0040", "name": "ML Supply Chain Compromise"}],
                "techniques": [
                    {"id": "AML.T0010", "name": "ML Supply Chain Compromise"}
                ],
                "explanation": "Loading untrusted models can compromise the ML supply chain",
            },
        },
        # For lack of input validation
        {
            "mitre_attack": {
                "tactics": [{"id": "TA0006", "name": "Credential Access"}],
                "techniques": [
                    {"id": "T1190", "name": "Exploit Public-Facing Application"}
                ],
                "explanation": "Missing input validation allows exploitation of the model endpoint",
            },
            "mitre_atlas": {
                "tactics": [{"id": "TA0036", "name": "ML Model Evasion"}],
                "techniques": [{"id": "AML.T0042", "name": "Adversarial ML"}],
                "explanation": "Lack of input validation makes the model vulnerable to adversarial examples",
            },
        },
        # For information leakage
        {
            "mitre_attack": {
                "tactics": [{"id": "TA0010", "name": "Exfiltration"}],
                "techniques": [{"id": "T1552", "name": "Unsecured Credentials"}],
                "explanation": "Detailed outputs can leak sensitive information",
            },
            "mitre_atlas": {
                "tactics": [{"id": "TA0032", "name": "Model Inference"}],
                "techniques": [{"id": "AML.T0017", "name": "Model Inversion"}],
                "explanation": "Per-sample loss information can enable model inversion attacks",
            },
        },
        # For data poisoning
        {
            "mitre_attack": {
                "tactics": [{"id": "TA0005", "name": "Defense Evasion"}],
                "techniques": [{"id": "T1195", "name": "Supply Chain Compromise"}],
                "explanation": "Poisoned training data can compromise the integrity of the model",
            },
            "mitre_atlas": {
                "tactics": [{"id": "TA0033", "name": "ML Data Poisoning"}],
                "techniques": [{"id": "AML.T0020", "name": "Poison Training Data"}],
                "explanation": "Lack of training data validation enables poisoning attacks",
            },
        },
    ]


@patch("agents.red_team_agent.client.chat.completions.create")
def test_analyze_ai_code_vulnerabilities(
    mock_openai_api, ai_model_with_vulnerabilities, mock_ai_vuln_response
):
    """Test that the Red Team Agent can identify AI-specific vulnerabilities."""
    # Setup the mock response
    mock_completion = MagicMock()
    mock_completion.choices[0].message.content = json.dumps(mock_ai_vuln_response)
    mock_openai_api.return_value = mock_completion

    # Test the function
    result = analyze_code_with_openai(
        ai_model_with_vulnerabilities, "vulnerable_ai_model.py"
    )

    # Verify the API was called
    mock_openai_api.assert_called_once()

    # Verify that GPT-4o model was used
    args, kwargs = mock_openai_api.call_args
    assert kwargs["model"] == "gpt-4o"

    # Verify the result has vulnerabilities
    assert "vulnerabilities" in result
    assert len(result["vulnerabilities"]) == 4

    # Check that we have different types of AI vulnerabilities
    vulnerability_types = set(
        v["vulnerability_type"] for v in result["vulnerabilities"]
    )
    assert "Insecure Deserialization" in vulnerability_types
    assert "Data Poisoning" in vulnerability_types
    assert "Input Validation" in vulnerability_types
    assert "Information Disclosure" in vulnerability_types

    # Check severity levels
    severity_count = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
    for vuln in result["vulnerabilities"]:
        severity_count[vuln["severity"]] += 1

    assert severity_count["CRITICAL"] == 1
    assert severity_count["HIGH"] == 2
    assert severity_count["MEDIUM"] == 1


@patch("agents.red_team_agent.client.chat.completions.create")
@patch("agents.red_team_agent.map_vulnerability_to_frameworks")
def test_framework_mapping_for_ai_vulnerabilities(
    mock_map_frameworks,
    mock_openai_api,
    ai_model_with_vulnerabilities,
    mock_ai_vuln_response,
    mock_ai_framework_mappings,
):
    """Test that AI vulnerabilities are correctly mapped to MITRE frameworks."""
    # Setup mock for analyze_code_with_openai
    mock_completion = MagicMock()
    mock_completion.choices[0].message.content = json.dumps(mock_ai_vuln_response)
    mock_openai_api.return_value = mock_completion

    # Setup mapping function to return appropriate framework mappings
    mapping_calls = 0

    def mapping_side_effect(vuln):
        nonlocal mapping_calls
        vuln["framework_mappings"] = mock_ai_framework_mappings[mapping_calls]
        mapping_calls += 1
        return vuln

    mock_map_frameworks.side_effect = mapping_side_effect

    # Call analyze_file which will use both analyze_code and map_frameworks
    result = analyze_file("vulnerable_ai_model.py", ai_model_with_vulnerabilities)

    # Verify that all vulnerabilities have framework mappings
    assert len(result["vulnerabilities"]) == 4
    for vuln in result["vulnerabilities"]:
        assert "framework_mappings" in vuln
        assert "mitre_attack" in vuln["framework_mappings"]
        assert "mitre_atlas" in vuln["framework_mappings"]

    # Verify that the ATLAS mappings include AI-specific techniques
    ai_techniques = []
    for vuln in result["vulnerabilities"]:
        atlas = vuln["framework_mappings"]["mitre_atlas"]
        for technique in atlas["techniques"]:
            ai_techniques.append(technique["id"])

    # Check for AI-specific technique IDs (AML prefix)
    assert any(tech.startswith("AML.") for tech in ai_techniques)


@pytest.mark.parametrize(
    "file_path,expected",
    [
        ("models/neural_network.py", True),
        ("src/ml_pipeline.py", True),
        ("tensorflow_model.py", True),
        ("image.jpg", False),
        ("node_modules/package.json", False),
    ],
)
def test_ai_file_filtering(file_path, expected):
    """Test that AI-related files are correctly identified for analysis."""
    from agents.red_team_agent import should_analyze_file

    assert should_analyze_file(file_path) == expected


if __name__ == "__main__":
    pytest.main(["-xvs", __file__])
