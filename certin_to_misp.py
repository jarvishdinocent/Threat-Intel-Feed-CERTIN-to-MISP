#!/usr/bin/env python3
import requests
import urllib3
import json
from datetime import datetime

# Disable SSL certificate verification warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# CERT-IN and MISP Configurations
# The URL for CERT-IN API to fetch threat intelligence data
CERTIN_URL = "https://ctix-certin.in/ctixapi/ctix21/collections/"
# Your CERT-IN username and password for authentication
CERTIN_USERNAME = ""  
CERTIN_PASSWORD = ""  
# URL for your MISP instance
MISP_URL = ""        
# Your MISP API Key for authentication
MISP_API_KEY = ""    

# Headers for CERT-IN API and MISP API
CERTIN_HEADERS = {
    "Accept": "application/taxii+json; version=2.1"  # Ensure correct format for retrieving CERT-IN data
}

MISP_HEADERS = {
    "Authorization": MISP_API_KEY,
    "Content-Type": "application/json",
    "Accept": "application/json"
}

def log(msg):
    """Log messages with timestamp."""
    print(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] {msg}")

# === Handling Pagination for Fetching STIX Data ===
def fetch_stix_data(collection_id):
    """Fetch STIX data from CERT-IN collection with pagination handling."""
    stix_url = f"{CERTIN_URL}{collection_id}/objects/"  # API endpoint to fetch STIX objects
    all_data = []  # List to store all fetched STIX objects
    start = 0
    chunk_size = 1000  # Number of objects to fetch in each API call

    while True:
        headers = CERTIN_HEADERS.copy()
        headers["Range"] = f"items {start}-{start + chunk_size - 1}"  # Specify the range of objects to fetch

        try:
            # Make the GET request to fetch the STIX data
            response = requests.get(stix_url, auth=(CERTIN_USERNAME, CERTIN_PASSWORD),
                                    headers=headers, verify=False, timeout=120)  # Increased timeout to 120s

            if response.status_code in [200, 206]:  # Successful response or partial data
                data = response.json()  # Convert response to JSON
                objects = data.get("objects", [])  # Extract 'objects' from the response data
                if not objects:
                    break  # If no objects found, exit the loop

                all_data.extend(objects)  # Add fetched objects to the all_data list
                log(f"[+] Received {len(objects)} STIX objects from range {start}-{start + chunk_size - 1}")

                if len(objects) < chunk_size:
                    break  # Stop fetching if fewer than expected objects were returned

                start += chunk_size  # Increment the range for the next request
            else:
                log(f"[!] Failed to fetch STIX for collection {collection_id}: HTTP {response.status_code}")
                break
        except Exception as e:
            log(f"[!] Exception fetching STIX: {e}")
            break

    return all_data  # Return the list of fetched STIX objects

# === Extract Relevant Data from STIX ===
def extract_stix_objects(stix_data):
    """Extract indicators, malware, attack patterns, and threat actors from the STIX data."""
    indicators, malwares, attack_patterns, tools, threat_actors = [], [], [], [], []  # Initialize lists for various threat data types
    lookup = {obj["id"]: obj for obj in stix_data if "id" in obj}  # Create a lookup dictionary for fast reference by object ID

    def process(obj):
        """Process different types of STIX objects."""
        if obj.get("type") == "indicator":
            pattern = obj.get("pattern", "")  # Get the pattern field from the indicator
            labels = obj.get("labels", [])  # Get the labels associated with the indicator
            if pattern:
                if "ipv4-addr" in pattern or "ip" in labels:
                    indicators.append({"type": "ip-src", "value": pattern})  # Add IP address indicators
                elif "url" in pattern or "url" in labels:
                    indicators.append({"type": "url", "value": pattern})  # Add URL indicators
                elif "file:hashes" in pattern or "hash" in labels:
                    indicators.append({"type": "md5", "value": pattern})  # Add file hash indicators
        elif obj.get("type") == "malware":
            malwares.append(f"Malware: {obj.get('name', 'Unnamed Malware')}")
        elif obj.get("type") == "attack-pattern":
            attack_patterns.append(f"Attack Pattern: {obj.get('name', 'Unnamed Attack Pattern')}")
        elif obj.get("type") == "tool":
            tools.append(f"Tool: {obj.get('name', 'Unnamed Tool')}")
        elif obj.get("type") == "threat-actor":
            threat_actors.append(f"Threat Actor: {obj.get('name', 'Unnamed Threat Actor')}")
        elif obj.get("type") == "report":
            # Handle references within reports
            for ref_id in obj.get("object_refs", []):
                if ref_id in lookup:
                    process(lookup[ref_id])  # Recursively process referenced objects

    for obj in stix_data:
        process(obj)  # Process each object in the STIX data

    log(f"[DEBUG] Extracted {len(indicators)} indicators, {len(malwares)} malwares, "
        f"{len(attack_patterns)} attack patterns, {len(tools)} tools, {len(threat_actors)} threat actors.")
    return indicators, malwares, attack_patterns, tools, threat_actors  # Return the extracted data

# === Map CERT-IN Title to MISP Event Name ===
def custom_event_name(certin_title):
    """Map CERT-IN collection title to a custom MISP event name."""
    mapping = {
        "TI_CL": "Threat Intelligence - Collection & Logging",
        "TI_GOV": "Threat Intelligence - Analysis & Monitoring",
        "TI_AM": "Threat Intelligence - Response & Elimination",
        "TI_RE": "Threat Intelligence - Research & Evaluation"
    }
    return mapping.get(certin_title, f"Unmapped Event - {certin_title}")  # Return the mapped event name

# === Create MISP Event with Data ===
def create_misp_event(title, description, indicators, malwares, attack_patterns, tools, threat_actors):
    """Create a new event in MISP."""
    if not (indicators or malwares or attack_patterns or tools or threat_actors):
        log(f"[!] No data to create event '{title}'")
        return

    attributes = []  # List to store attributes for the MISP event

    # Add indicators to attributes
    for i in indicators:
        attributes.append({
            "type": i["type"],
            "value": i["value"],
            "category": "Network activity" if i["type"] in ["ip-src", "url"] else "Payload delivery"
        })

    # Add malwares, attack-patterns, tools, and threat-actors as comments
    for entry in malwares + attack_patterns + tools + threat_actors:
        attributes.append({
            "type": "comment",
            "value": entry,
            "category": "Internal reference"
        })

    if not attributes:
        log(f"[!] No attributes to add for event '{title}'")
        return

    # Prepare the payload for the MISP event
    payload = {
        "Event": {
            "info": title,
            "analysis": 0,
            "threat_level_id": 2,
            "distribution": 1,
            "published": True,
            "Attribute": attributes,
            "Tag": [{"name": "source:cert-in-script"}]  # Tag for identifying the source
        }
    }

    log(f"[DEBUG] Payload for MISP Event: {json.dumps(payload, indent=4)}")

    try:
        # Make a POST request to create the MISP event
        response = requests.post(f"{MISP_URL}/events", headers=MISP_HEADERS, json=payload,
                                 verify=False, timeout=120)

        log(f"[DEBUG] MISP API Response Status: {response.status_code}")

        if response.status_code == 200:
            log(f"[✔] Event created in MISP: {title}")
        else:
            log(f"[!] Failed to create event '{title}' - Response: {response.status_code} - {response.text}")
    except Exception as e:
        log(f"[!] Exception creating MISP event: {e}")

# === Fetch CERT-IN Collections and Process Data ===
def fetch_certin_collections():
    """Fetch CERT-IN collections and process STIX data."""
    try:
        # Make a GET request to fetch CERT-IN collections
        response = requests.get(CERTIN_URL, auth=(CERTIN_USERNAME, CERTIN_PASSWORD),
                                headers=CERTIN_HEADERS, verify=False, timeout=60)
        if response.status_code != 200:
            log(f"[!] Failed to fetch collections: HTTP {response.status_code}")
            return []

        collections = response.json().get("collections", [])  # Extract collections from the response
        for col in collections:
            title = col["title"]  # Get the collection title
            event_title = custom_event_name(title)  # Map collection title to MISP event name
            log(f"[→] Processing collection: {title} → MISP Event: {event_title}")

            stix_data = fetch_stix_data(col["id"])  # Fetch STIX data for the collection
            if not stix_data:
                log(f"[!] No STIX data for collection {title}")
                continue

            # Extract relevant data from the STIX objects
            indicators, malwares, attack_patterns, tools, threat_actors = extract_stix_objects(stix_data)

            # Create the MISP event and add the extracted data
            create_misp_event(event_title, col.get("description", "No description"), indicators, malwares, attack_patterns, tools, threat_actors)

    except Exception as e:
        log(f"[!] Exception during collection fetch: {e}")

# === Main Function to Run Script Once ===
def run_once():
    """Main function to run the script once."""
    log("[*] Starting CERT-IN to MISP sync...")
    fetch_certin_collections()  # Fetch and process CERT-IN collections
    log("[✔] CERT-IN to MISP sync complete.")  # Sync complete message

# Start the script
if __name__ == "__main__":
    run_once()
