#!/usr/bin/env python3  # Indicates the script should be run using Python 3

# === IMPORTS ===
import requests            # For making HTTP(S) requests
import urllib3             # To manage SSL warnings
import json                # For JSON parsing and formatting
import re                  # For extracting values using regular expressions
import time                # For sleep/retry logic
from datetime import datetime  # For timestamps in logging

# === DISABLE SSL WARNINGS ===
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)  # Suppress SSL warnings for self-signed certs

# === CONFIGURATION SECTION ===

CERTIN_URL = ""           # Base URL of CERT-IN TAXII 2.1 feed (include trailing slash)
CERTIN_USERNAME = ""      # CERT-IN TAXII username
CERTIN_PASSWORD = ""      # CERT-IN TAXII password

MISP_URL = ""             # Base URL of MISP instance (e.g., https://misp.local)
MISP_API_KEY = ""         # MISP API authentication key
MISP_VERIFYCERT = False   # Set to True if using valid SSL cert, False for self-signed

# HTTP headers required for CERT-IN API
CERTIN_HEADERS = {
    "Accept": "application/taxii+json; version=2.1"
}

# HTTP headers for MISP API
MISP_HEADERS = {
    "Authorization": MISP_API_KEY,
    "Content-Type": "application/json",
    "Accept": "application/json"
}

# === LOGGING FUNCTION ===
def log(msg):
    """Logs message with a timestamp."""
    print(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] {msg}")

# === STIX PARSER FUNCTION ===
def extract_indicators(stix_data):
    """
    Extracts indicators (IP, URL, MD5) from STIX pattern strings using regex.
    Returns a list of MISP-compatible indicator dicts.
    """
    indicators = []  # List to hold extracted indicators

    for item in stix_data:
        if item.get('type') != 'indicator':  # Skip non-indicator objects
            continue

        pattern = item.get('pattern', '')  # Extract pattern field

        # Extract IPv4 addresses
        if "[ipv4-addr:value" in pattern:
            match = re.search(r"\[ipv4-addr:value\s*=\s*'([^']+)'\]", pattern)
            if match:
                indicators.append({'type': 'ip-src', 'value': match.group(1)})

        # Extract URLs
        elif "[url:value" in pattern:
            match = re.search(r"\[url:value\s*=\s*'([^']+)'\]", pattern)
            if match:
                indicators.append({'type': 'url', 'value': match.group(1)})

        # Extract MD5 hashes
        elif "[file:hashes.'MD5'" in pattern:
            match = re.search(r"\[file:hashes\.'MD5'\s*=\s*'([^']+)'\]", pattern)
            if match:
                indicators.append({'type': 'md5', 'value': match.group(1)})

    return indicators  # Return list of structured indicators

# === FETCH STIX OBJECTS ===
def fetch_stix_data(collection_id):
    """
    Fetches all STIX objects for a given collection ID from CERT-IN TAXII server.
    Handles pagination manually (if implemented in future).
    """
    stix_url = f"{CERTIN_URL}{collection_id}/objects/"
    all_data = []  # Accumulator for all fetched objects

    while stix_url:
        try:
            response = requests.get(
                stix_url,
                auth=(CERTIN_USERNAME, CERTIN_PASSWORD),
                headers=CERTIN_HEADERS,
                verify=False,
                timeout=60
            )

            # Handle successful response (full or partial)
            if response.status_code in (200, 206):
                try:
                    data = response.json()
                except Exception as e:
                    log(f"[!] Failed to parse JSON for collection {collection_id}: {e}")
                    return []

                objects = data.get('objects', [])
                if objects:
                    log(f"[+] {len(objects)} STIX objects found in collection {collection_id}.")
                    all_data.extend(objects)
                else:
                    log(f"[!] No 'objects' found in response for collection {collection_id}.")

                stix_url = None  # Exit after one page for now
            else:
                log(f"[!] Failed to fetch STIX for {collection_id}: HTTP {response.status_code}")
                return []

        except Exception as e:
            log(f"[!] Exception fetching STIX data for collection {collection_id}: {e}")
            return []

    return all_data  # Return all fetched objects

# === FETCH COLLECTIONS ===
def fetch_certin_collections():
    """
    Fetches the list of collections (feeds) available from CERT-IN TAXII API.
    """
    try:
        response = requests.get(
            CERTIN_URL,
            auth=(CERTIN_USERNAME, CERTIN_PASSWORD),
            headers=CERTIN_HEADERS,
            verify=False,
            timeout=60
        )

        if response.status_code == 200:
            collections = response.json().get("collections", [])
            log(f"[+] Found {len(collections)} collections.")
            log("[*] Collection titles returned from CERT-IN:")
            for col in collections:
                log(f"    - {col['title']}")
            return collections  # Return parsed collection list
        else:
            log(f"[!] CERT-IN fetch failed: HTTP {response.status_code}")
            return []

    except Exception as e:
        log(f"[!] Exception fetching CERT-IN collections: {e}")
        return []

# === CREATE MISP EVENT ===
def create_misp_event(title, description, indicators):
    """
    Creates a new MISP event with the extracted indicators and collection description.
    Includes basic retry logic for network errors/timeouts.
    """
    if not indicators:
        log(f"[!] No indicators to add for '{title}'")
        return

    # Define MISP-compatible event payload
    payload = {
        "Event": {
            "info": f"CERT-IN Feed: {title}",
            "analysis": 0,
            "threat_level_id": 2,
            "distribution": 1,
            "published": True,
            "Attribute": indicators + [{
                "type": "comment",
                "category": "Internal reference",
                "value": description or "No description provided"
            }],
            "Tag": [{"name": "source:cert-in-script"}]
        }
    }

    # Try up to 2 times to POST event to MISP
    for attempt in range(2):
        try:
            response = requests.post(
                f"{MISP_URL}/events",
                headers=MISP_HEADERS,
                json=payload,
                verify=MISP_VERIFYCERT,
                timeout=180  # Increased timeout for large payloads
            )

            if response.status_code == 200 and "Event" in response.text:
                log(f"[+] MISP event created: {title}")
                return
            else:
                log(f"[!] Failed to create event: {title}. Status: {response.status_code}")
                log(response.text)
                return

        except requests.exceptions.ReadTimeout:
            log(f"[!] Timeout on attempt {attempt+1} for '{title}' — retrying..." if attempt == 0 else f"[!] Final timeout.")
            if attempt == 0:
                time.sleep(5)  # Wait before retry
            else:
                return

        except Exception as e:
            log(f"[!] Exception while posting to MISP: {e}")
            return

# === MAIN SYNC FUNCTION ===
def run_certin_sync():
    """
    Main driver: fetches CERT-IN collections, fetches STIX data per collection,
    extracts indicators, and posts to MISP.
    """
    log("[*] Starting CERT-IN feed sync...")

    collections = fetch_certin_collections()
    if not collections:
        log("[!] No collections to process.")
        return

    for collection in collections:
        log(f"[>] Processing collection: {collection['title']}")
        stix_data = fetch_stix_data(collection['id'])

        if stix_data:
            indicators = extract_indicators(stix_data)
            log(f"[+] Extracted {len(indicators)} indicators.")
            create_misp_event(collection['title'], collection.get('description', ''), indicators)
        else:
            log(f"[!] No STIX data found for: {collection['title']}")

# === SCRIPT ENTRY POINT ===
if __name__ == "__main__":
    run_certin_sync()  # Start the script execution
