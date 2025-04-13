#!/usr/bin/env python3
"""
Data Fetcher Module

This module provides functions to fetch and parse MITRE ATT&CK and ATLAS data
using the official libraries and recommended approaches. It includes caching
mechanisms to minimize external API calls and provides a structured interface
for accessing threat intelligence data.

Functions:
    fetch_mitre_attack_data: Fetches MITRE ATT&CK data for a specific domain
    fetch_mitre_atlas_data: Fetches MITRE ATLAS data from the official GitHub repo
    get_attack_techniques: Returns all ATT&CK techniques as a list
    get_atlas_techniques: Returns all ATLAS techniques as a list
    get_tactics_by_technique: Returns tactics associated with a technique
    map_vulnerability_to_attack: Maps vulnerabilities to ATT&CK framework
    map_vulnerability_to_atlas: Maps vulnerabilities to ATLAS framework
"""

import os
import json
import yaml
import requests
import sys
import logging
import importlib.util
import traceback
import time
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List, Optional, Union, Any, Tuple
from dotenv import load_dotenv

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
)
logger = logging.getLogger(__name__)

# Global flags and variables
MITRE_ATTACK_AVAILABLE = False
CACHE_EXPIRY_DAYS = 7  # Number of days before cache expires
mitreattack_module = None

# Try to import mitreattack package
try:
    # Check if package is available
    mitreattack_spec = importlib.util.find_spec("mitreattack")
    if mitreattack_spec:
        logger.info(f"mitreattack module found at: {mitreattack_spec.origin}")

        # Import the package
        import mitreattack
        from mitreattack.collections import stix_to_collection

        mitreattack_module = mitreattack

        logger.info(f"Successfully imported mitreattack module: {mitreattack.__file__}")

        # Verify if the module has the necessary functions
        required_funcs = ["stix_to_collection", "STIXToCollection"]
        available_funcs = [func for func in dir(mitreattack) if func in required_funcs]
        logger.info(f"Available mitreattack functions: {available_funcs}")

        if available_funcs:
            MITRE_ATTACK_AVAILABLE = True
            logger.info("Required mitreattack functions found")
        else:
            logger.warning(f"Required functions not found in mitreattack")
    else:
        logger.warning(
            "mitreattack-python package not found. Install it using: "
            "pip install mitreattack-python"
        )
except ImportError as e:
    logger.warning(
        f"Error importing mitreattack-python package: {str(e)}. Install it using: "
        "pip install mitreattack-python"
    )
    logger.debug(traceback.format_exc())

# Load environment variables
load_dotenv()

# Constants
DATA_DIR = Path(__file__).parent.parent / "data"
MITRE_ATTACK_DIR = DATA_DIR / "mitre_attack"
MITRE_ATLAS_DIR = DATA_DIR / "mitre_atlas"
ATLAS_YAML_URL = (
    "https://raw.githubusercontent.com/mitre-atlas/atlas-data/main/dist/ATLAS.yaml"
)

# GitHub URLs for MITRE ATT&CK STIX data
ATTACK_DOMAIN_URLS = {
    "enterprise": "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json",
    "mobile": "https://raw.githubusercontent.com/mitre/cti/master/mobile-attack/mobile-attack.json",
    "ics": "https://raw.githubusercontent.com/mitre/cti/master/ics-attack/ics-attack.json",
}


def ensure_data_directories() -> None:
    """
    Ensure the data directories exist for storing cached data.

    This function creates the necessary directory structure for storing
    MITRE ATT&CK and ATLAS data if they don't already exist.
    """
    MITRE_ATTACK_DIR.mkdir(parents=True, exist_ok=True)
    MITRE_ATLAS_DIR.mkdir(parents=True, exist_ok=True)


def is_cache_valid(cache_file: Path, expiry_days: int = CACHE_EXPIRY_DAYS) -> bool:
    """
    Check if a cached file is valid based on its age.

    Args:
        cache_file: Path to the cached file
        expiry_days: Number of days before cache expires

    Returns:
        bool: True if the cache is valid, False otherwise
    """
    if not cache_file.exists():
        return False

    file_age = datetime.now() - datetime.fromtimestamp(cache_file.stat().st_mtime)
    return file_age.days < expiry_days


def fetch_mitre_attack_data(
    domain: str = "enterprise", version: Optional[str] = None
) -> Optional[Dict]:
    """
    Fetches MITRE ATT&CK data using the official mitreattack-python library.

    If direct API access via the mitreattack library isn't available, falls back to
    using the MITRE ATT&CK STIX data from a cached file or from the official GitHub repo.

    Args:
        domain: ATT&CK domain ('enterprise', 'mobile', or 'ics')
        version: Optional version of ATT&CK data

    Returns:
        Dict: ATT&CK data in structured form, or None if retrieval fails
    """
    ensure_data_directories()

    # Local cache file path
    cache_file = (
        MITRE_ATTACK_DIR / f"{domain}_{'latest' if version is None else version}.json"
    )
    cache_metadata_file = cache_file.with_suffix(".meta")

    # Check if cache is valid before attempting to use it
    if is_cache_valid(cache_file):
        logger.info(f"Using valid cached MITRE ATT&CK data: {cache_file}")
        try:
            with open(cache_file, "r", encoding="utf-8") as f:
                return json.load(f)
        except (json.JSONDecodeError, IOError) as e:
            logger.warning(
                f"Error reading cached ATT&CK data: {str(e)}. Will attempt to fetch fresh data."
            )

    # If mitreattack is available, try to use it
    if MITRE_ATTACK_AVAILABLE:
        try:
            logger.info(
                f"Attempting to fetch MITRE ATT&CK {domain} data using mitreattack API"
            )

            # Get the correct URL for the domain
            if domain not in ATTACK_DOMAIN_URLS:
                raise ValueError(
                    f"Unsupported domain: {domain}. Use 'enterprise', 'mobile', or 'ics'."
                )

            stix_url = ATTACK_DOMAIN_URLS[domain]

            # Fetch the STIX bundle
            logger.info(f"Fetching STIX data from {stix_url}")
            response = requests.get(stix_url, timeout=30)
            response.raise_for_status()

            stix_bundle = response.json()

            # Enhance the bundle with a collection object using mitreattack
            collection_name = f"MITRE ATT&CK {domain.capitalize()}"
            collection_version = version or "latest"

            logger.info(
                f"Enhancing STIX bundle with collection object: {collection_name}"
            )
            enhanced_bundle = stix_to_collection.STIXToCollection.stix_to_collection(
                stix_bundle,
                collection_name,
                collection_version,
                f"MITRE ATT&CK data for {domain} domain",
            )

            # Cache the enhanced data
            with open(cache_file, "w", encoding="utf-8") as f:
                json.dump(enhanced_bundle, f)

            # Save metadata about when this cache was created
            with open(cache_metadata_file, "w", encoding="utf-8") as f:
                metadata = {
                    "retrieved_date": datetime.now().isoformat(),
                    "domain": domain,
                    "version": version or "latest",
                    "source": "mitreattack API",
                }
                json.dump(metadata, f)

            logger.info(
                f"Successfully fetched MITRE ATT&CK {domain} data via mitreattack API"
            )
            return enhanced_bundle

        except Exception as e:
            logger.error(f"Error using mitreattack API: {str(e)}")
            logger.debug(traceback.format_exc())
            logger.info("Falling back to direct STIX download...")

    # Fallback to direct STIX download if mitreattack API fails or is not available
    try:
        if domain not in ATTACK_DOMAIN_URLS:
            raise ValueError(
                f"Unsupported domain: {domain}. Use 'enterprise', 'mobile', or 'ics'."
            )

        stix_url = ATTACK_DOMAIN_URLS[domain]

        logger.info(f"Downloading MITRE ATT&CK data from {stix_url}")
        response = requests.get(stix_url, timeout=30)
        response.raise_for_status()

        attack_data = response.json()

        # Cache the data
        with open(cache_file, "w", encoding="utf-8") as f:
            json.dump(attack_data, f)

        # Save metadata about when this cache was created
        with open(cache_metadata_file, "w", encoding="utf-8") as f:
            metadata = {
                "retrieved_date": datetime.now().isoformat(),
                "domain": domain,
                "version": version or "latest",
                "source": "direct STIX download",
            }
            json.dump(metadata, f)

        logger.info(
            f"Successfully fetched MITRE ATT&CK {domain} data via direct STIX download"
        )
        return attack_data

    except requests.RequestException as e:
        logger.error(f"Network error fetching MITRE ATT&CK data: {str(e)}")
        # Try to load from cache as last resort, even if it's expired
        if cache_file.exists():
            logger.warning(f"Falling back to potentially outdated cache: {cache_file}")
            try:
                with open(cache_file, "r", encoding="utf-8") as f:
                    return json.load(f)
            except (json.JSONDecodeError, IOError) as e:
                logger.error(f"Error reading cached ATT&CK data: {str(e)}")

        logger.error("Could not fetch or load MITRE ATT&CK data")
        return None
    except Exception as e:
        logger.error(f"Unexpected error fetching MITRE ATT&CK data: {str(e)}")
        logger.debug(traceback.format_exc())

        # Try to load from cache as last resort, even if it's expired
        if cache_file.exists():
            logger.warning(f"Falling back to potentially outdated cache: {cache_file}")
            try:
                with open(cache_file, "r", encoding="utf-8") as f:
                    return json.load(f)
            except (json.JSONDecodeError, IOError) as e:
                logger.error(f"Error reading cached ATT&CK data: {str(e)}")

        logger.error("Could not fetch or load MITRE ATT&CK data")
        return None


def fetch_mitre_atlas_data() -> Optional[Dict]:
    """
    Fetches MITRE ATLAS data from the official GitHub repository.

    Returns:
        Dict: ATLAS data containing tactics, techniques, matrices,
        and case studies, or None if retrieval fails
    """
    ensure_data_directories()

    # Local cache file path
    cache_file = MITRE_ATLAS_DIR / "ATLAS.yaml"
    cache_metadata_file = cache_file.with_suffix(".meta")

    # Check if cache is valid
    if is_cache_valid(cache_file):
        logger.info(f"Using valid cached MITRE ATLAS data: {cache_file}")
        try:
            with open(cache_file, "r", encoding="utf-8") as f:
                return yaml.safe_load(f)
        except (yaml.YAMLError, IOError) as e:
            logger.warning(
                f"Error reading cached ATLAS data: {str(e)}. Will attempt to fetch fresh data."
            )

    try:
        # Fetch the latest ATLAS.yaml file from GitHub
        logger.info(f"Fetching MITRE ATLAS data from {ATLAS_YAML_URL}")
        response = requests.get(ATLAS_YAML_URL, timeout=30)
        response.raise_for_status()  # Raises an exception for HTTP errors

        # Parse the YAML content
        atlas_data = yaml.safe_load(response.text)

        # Cache the data locally
        with open(cache_file, "w", encoding="utf-8") as f:
            yaml.dump(atlas_data, f)

        # Save metadata about when this cache was created
        with open(cache_metadata_file, "w", encoding="utf-8") as f:
            metadata = {
                "retrieved_date": datetime.now().isoformat(),
                "source": ATLAS_YAML_URL,
            }
            json.dump(metadata, f)

        logger.info("Successfully fetched MITRE ATLAS data")
        return atlas_data

    except requests.RequestException as e:
        logger.error(f"Network error fetching MITRE ATLAS data: {str(e)}")
        # Try to load from cache as last resort, even if it's expired
        if cache_file.exists():
            logger.warning(f"Falling back to potentially outdated cache: {cache_file}")
            try:
                with open(cache_file, "r", encoding="utf-8") as f:
                    return yaml.safe_load(f)
            except (yaml.YAMLError, IOError) as e:
                logger.error(f"Error reading cached ATLAS data: {str(e)}")

        logger.error("Could not fetch or load MITRE ATLAS data")
        return None
    except Exception as e:
        logger.error(f"Unexpected error fetching MITRE ATLAS data: {str(e)}")
        logger.debug(traceback.format_exc())

        # Try to load from cache as last resort, even if it's expired
        if cache_file.exists():
            logger.warning(f"Falling back to potentially outdated cache: {cache_file}")
            try:
                with open(cache_file, "r", encoding="utf-8") as f:
                    return yaml.safe_load(f)
            except (yaml.YAMLError, IOError) as e:
                logger.error(f"Error reading cached ATLAS data: {str(e)}")

        logger.error("Could not fetch or load MITRE ATLAS data")
        return None


def get_attack_techniques(attack_data: Optional[Dict] = None) -> List[Dict]:
    """
    Returns all ATT&CK techniques as a convenient list.

    Args:
        attack_data: Preloaded ATT&CK data. If None, will fetch it.

    Returns:
        List[Dict]: List of technique objects
    """
    if attack_data is None:
        attack_data = fetch_mitre_attack_data()

    if not attack_data:
        logger.warning("No ATT&CK data available to extract techniques from")
        return []

    # Extract techniques from the ATT&CK data
    techniques = []

    try:
        for obj in attack_data.get("objects", []):
            if obj.get("type") == "attack-pattern":
                techniques.append(obj)

        logger.info(f"Extracted {len(techniques)} techniques from ATT&CK data")
        return techniques
    except Exception as e:
        logger.error(f"Error extracting techniques from ATT&CK data: {str(e)}")
        logger.debug(traceback.format_exc())
        return []


def get_atlas_techniques() -> List[Dict]:
    """
    Returns all ATLAS techniques as a list.

    Returns:
        List[Dict]: List of technique objects
    """
    atlas_data = fetch_mitre_atlas_data()
    if not atlas_data:
        logger.warning("No ATLAS data available to extract techniques from")
        return []

    # Extract techniques from the ATLAS data
    try:
        if "matrices" in atlas_data and atlas_data["matrices"]:
            first_matrix = atlas_data["matrices"][0]
            techniques = first_matrix.get("techniques", [])
            logger.info(f"Extracted {len(techniques)} techniques from ATLAS data")
            return techniques
    except Exception as e:
        logger.error(f"Error extracting techniques from ATLAS data: {str(e)}")
        logger.debug(traceback.format_exc())

    return []


def get_tactics_by_technique(attack_data: Dict, technique_id: str) -> List[Dict]:
    """
    Returns tactics associated with a technique.

    Args:
        attack_data: The ATT&CK data
        technique_id: The ID of the technique

    Returns:
        List[Dict]: List of tactic objects
    """
    if not attack_data:
        logger.warning(
            f"No ATT&CK data available to find tactics for technique {technique_id}"
        )
        return []

    try:
        # Find the technique by ID
        technique = None
        for obj in attack_data.get("objects", []):
            if obj.get("type") == "attack-pattern" and obj.get("id") == technique_id:
                technique = obj
                break

        if not technique:
            logger.warning(f"Technique with ID {technique_id} not found in ATT&CK data")
            return []

        # Find tactics related to this technique through kill-chain-phases
        tactics = []
        kill_chain_phases = technique.get("kill_chain_phases", [])

        for phase in kill_chain_phases:
            if phase.get("kill_chain_name") == "mitre-attack":
                phase_name = phase.get("phase_name")

                # Find the corresponding tactic object
                for obj in attack_data.get("objects", []):
                    if (
                        obj.get("type") == "x-mitre-tactic"
                        and obj.get("x_mitre_shortname") == phase_name
                    ):
                        tactics.append(obj)

        logger.info(f"Found {len(tactics)} tactics for technique {technique_id}")
        return tactics
    except Exception as e:
        logger.error(f"Error getting tactics for technique {technique_id}: {str(e)}")
        logger.debug(traceback.format_exc())
        return []


def map_vulnerability_to_attack(vulnerability_data: Dict) -> List[Dict]:
    """
    Maps a vulnerability to MITRE ATT&CK tactics and techniques.

    Args:
        vulnerability_data: Information about the vulnerability with 'keywords' field

    Returns:
        List[Dict]: List of matching ATT&CK techniques and tactics
    """
    attack_data = fetch_mitre_attack_data()
    if not attack_data:
        logger.warning("No ATT&CK data available for vulnerability mapping")
        return []

    # Validate input
    if not isinstance(vulnerability_data, dict) or "keywords" not in vulnerability_data:
        logger.error(
            "Invalid vulnerability data format. Must be a dict with 'keywords' field."
        )
        return []

    if not vulnerability_data.get("keywords"):
        logger.warning("No keywords provided in vulnerability data for matching")
        return []

    matches = []
    techniques = get_attack_techniques(attack_data)

    for technique in techniques:
        # Example simple keyword matching
        if _is_vulnerability_matching_technique(vulnerability_data, technique):
            tactics = get_tactics_by_technique(attack_data, technique.get("id", ""))
            tactic_name = tactics[0].get("name", "") if tactics else ""

            external_id = ""
            for ref in technique.get("external_references", []):
                if ref.get("source_name") == "mitre-attack":
                    external_id = ref.get("external_id", "")
                    break

            matches.append(
                {
                    "technique_id": external_id,
                    "technique_name": technique.get("name", ""),
                    "technique_description": technique.get("description", ""),
                    "tactic": tactic_name,
                }
            )

    logger.info(f"Found {len(matches)} ATT&CK matches for vulnerability")
    return matches


def map_vulnerability_to_atlas(vulnerability_data: Dict) -> List[Dict]:
    """
    Maps a vulnerability to MITRE ATLAS tactics and techniques.

    Args:
        vulnerability_data: Information about the vulnerability with 'keywords' field

    Returns:
        List[Dict]: List of matching ATLAS techniques and tactics
    """
    atlas_data = fetch_mitre_atlas_data()
    if not atlas_data:
        logger.warning("No ATLAS data available for vulnerability mapping")
        return []

    # Validate input
    if not isinstance(vulnerability_data, dict) or "keywords" not in vulnerability_data:
        logger.error(
            "Invalid vulnerability data format. Must be a dict with 'keywords' field."
        )
        return []

    if not vulnerability_data.get("keywords"):
        logger.warning("No keywords provided in vulnerability data for matching")
        return []

    try:
        if "matrices" not in atlas_data or not atlas_data["matrices"]:
            logger.warning("No matrices found in ATLAS data")
            return []

        first_matrix = atlas_data["matrices"][0]
        techniques = first_matrix.get("techniques", [])
        tactics = first_matrix.get("tactics", [])

        matches = _find_matching_techniques(vulnerability_data, techniques, tactics)
        logger.info(f"Found {len(matches)} ATLAS matches for vulnerability")
        return matches

    except Exception as e:
        logger.error(f"Error mapping vulnerability to ATLAS: {str(e)}")
        logger.debug(traceback.format_exc())
        return []


def _is_vulnerability_matching_technique(
    vulnerability_data: Dict, technique: Dict
) -> bool:
    """
    Check if a technique matches the vulnerability data based on keywords.

    Args:
        vulnerability_data: Data about the vulnerability with keywords
        technique: Technique data to match against

    Returns:
        bool: True if there's a match, False otherwise
    """
    # Get keywords from vulnerability data
    keywords = vulnerability_data.get("keywords", [])

    # Check for match in technique name
    if any(
        keyword.lower() in technique.get("name", "").lower() for keyword in keywords
    ):
        return True

    # Check for match in technique description
    if any(
        keyword.lower() in technique.get("description", "").lower()
        for keyword in keywords
    ):
        return True

    return False


def _find_matching_techniques(
    vulnerability_data: Dict, techniques: List[Dict], tactics: List[Dict]
) -> List[Dict]:
    """
    Find ATLAS techniques matching the vulnerability data.

    Args:
        vulnerability_data: Data about the vulnerability with keywords
        techniques: List of ATLAS techniques to check
        tactics: List of ATLAS tactics for reference

    Returns:
        List[Dict]: List of matching techniques with tactic information
    """
    matches = []
    for technique in techniques:
        if _is_technique_matching(vulnerability_data, technique):
            tactic_name = _find_tactic_name(technique, tactics)
            matches.append(
                {
                    "technique_id": technique.get("id", ""),
                    "technique_name": technique.get("name", ""),
                    "technique_description": technique.get("description", ""),
                    "tactic": tactic_name,
                }
            )
    return matches


def _is_technique_matching(vulnerability_data: Dict, technique: Dict) -> bool:
    """
    Check if an ATLAS technique matches the vulnerability data.

    Args:
        vulnerability_data: Vulnerability information with keywords
        technique: ATLAS technique to check

    Returns:
        bool: True if there's a match, False otherwise
    """
    # Get keywords from vulnerability data
    keywords = vulnerability_data.get("keywords", [])

    # Check for match in technique name
    if any(
        keyword.lower() in technique.get("name", "").lower() for keyword in keywords
    ):
        return True

    # Check for match in technique description
    if any(
        keyword.lower() in technique.get("description", "").lower()
        for keyword in keywords
    ):
        return True

    return False


def _find_tactic_name(technique: Dict, tactics: List[Dict]) -> str:
    """
    Find the tactic name for a given ATLAS technique.

    Args:
        technique: ATLAS technique object
        tactics: List of all ATLAS tactics

    Returns:
        str: Name of the tactic, or empty string if not found
    """
    for tactic_id in technique.get("tactic_refs", []):
        for tactic in tactics:
            if tactic.get("id") == tactic_id:
                return tactic.get("name", "")
    return ""


def refresh_all_data() -> Dict[str, bool]:
    """
    Force refresh all cached data.

    Returns:
        Dict[str, bool]: Status of each refresh operation
    """
    results = {
        "enterprise_attack": False,
        "mobile_attack": False,
        "ics_attack": False,
        "atlas": False,
    }

    try:
        # Remove all cache files first
        for domain in ["enterprise", "mobile", "ics"]:
            cache_file = MITRE_ATTACK_DIR / f"{domain}_latest.json"
            if cache_file.exists():
                cache_file.unlink()

            # Also remove metadata file if it exists
            meta_file = cache_file.with_suffix(".meta")
            if meta_file.exists():
                meta_file.unlink()

        atlas_cache = MITRE_ATLAS_DIR / "ATLAS.yaml"
        if atlas_cache.exists():
            atlas_cache.unlink()

        atlas_meta = atlas_cache.with_suffix(".meta")
        if atlas_meta.exists():
            atlas_meta.unlink()

        # Now fetch fresh data
        for domain in ["enterprise", "mobile", "ics"]:
            data = fetch_mitre_attack_data(domain)
            results[f"{domain}_attack"] = data is not None

        atlas_data = fetch_mitre_atlas_data()
        results["atlas"] = atlas_data is not None

        return results
    except Exception as e:
        logger.error(f"Error during data refresh: {str(e)}")
        logger.debug(traceback.format_exc())
        return results


def test_data_fetchers() -> Dict[str, Any]:
    """
    Test all data fetchers and return results.

    Returns:
        Dict[str, Any]: Test results with counts and status
    """
    results = {
        "status": "success",
        "errors": [],
        "enterprise_attack": {"status": "not tested", "technique_count": 0},
        "mobile_attack": {"status": "not tested", "technique_count": 0},
        "ics_attack": {"status": "not tested", "technique_count": 0},
        "atlas": {"status": "not tested", "technique_count": 0},
    }

    try:
        # Test MITRE ATT&CK Enterprise data
        logger.info("Testing MITRE ATT&CK Enterprise data fetcher...")
        start_time = time.time()
        enterprise_data = fetch_mitre_attack_data("enterprise")
        if enterprise_data:
            techniques = get_attack_techniques(enterprise_data)
            results["enterprise_attack"] = {
                "status": "success",
                "technique_count": len(techniques),
                "fetch_time_seconds": round(time.time() - start_time, 2),
            }
        else:
            results["enterprise_attack"] = {
                "status": "failed",
                "error": "Could not fetch or load MITRE ATT&CK Enterprise data",
            }
            results["errors"].append("Enterprise ATT&CK data fetch failed")

        # Test MITRE ATLAS data
        logger.info("Testing MITRE ATLAS data fetcher...")
        start_time = time.time()
        atlas_data = fetch_mitre_atlas_data()
        if atlas_data:
            techniques = get_atlas_techniques()
            results["atlas"] = {
                "status": "success",
                "technique_count": len(techniques),
                "fetch_time_seconds": round(time.time() - start_time, 2),
            }
        else:
            results["atlas"] = {
                "status": "failed",
                "error": "Could not fetch or load MITRE ATLAS data",
            }
            results["errors"].append("ATLAS data fetch failed")

        # Overall status
        if results["errors"]:
            results["status"] = (
                "partial failure"
                if results["enterprise_attack"]["status"] == "success"
                or results["atlas"]["status"] == "success"
                else "failure"
            )

        return results
    except Exception as e:
        logger.error(f"Error during data fetcher test: {str(e)}")
        logger.debug(traceback.format_exc())
        results["status"] = "error"
        results["errors"].append(str(e))
        return results


if __name__ == "__main__":
    # Test all data fetchers and print results
    results = test_data_fetchers()

    print("\n=== Data Fetcher Test Results ===")
    print(f"Overall Status: {results['status'].upper()}")

    if results.get("enterprise_attack", {}).get("status") == "success":
        print(f"\nMITRE ATT&CK Enterprise: SUCCESS")
        print(
            f"- Retrieved {results['enterprise_attack']['technique_count']} techniques"
        )
        print(
            f"- Fetch time: {results['enterprise_attack']['fetch_time_seconds']} seconds"
        )
    else:
        print(f"\nMITRE ATT&CK Enterprise: FAILED")
        if "error" in results.get("enterprise_attack", {}):
            print(f"- Error: {results['enterprise_attack']['error']}")

    if results.get("atlas", {}).get("status") == "success":
        print(f"\nMITRE ATLAS: SUCCESS")
        print(f"- Retrieved {results['atlas']['technique_count']} techniques")
        print(f"- Fetch time: {results['atlas']['fetch_time_seconds']} seconds")
    else:
        print(f"\nMITRE ATLAS: FAILED")
        if "error" in results.get("atlas", {}):
            print(f"- Error: {results['atlas']['error']}")

    if results["errors"]:
        print("\nErrors encountered:")
        for error in results["errors"]:
            print(f"- {error}")
