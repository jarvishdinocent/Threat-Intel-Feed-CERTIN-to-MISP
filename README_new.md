# Threat-Intel-Feed-CERTIN-to-MISP

The Threat-Intel-Feed-CERTIN-to-MISP repository offers an automated pipeline for ingesting CERT-IN (Indian Computer Emergency Response Team) threat intelligence data into the MISP (Malware Information Sharing Platform & Threat Sharing). By leveraging CERT-IN's STIX-based threat feeds, this project enables seamless integration into MISP for actionable cybersecurity insights. 

This solution aims to enhance the collaboration, analysis, and sharing of critical cyber threat intelligence in a standardized format, allowing organizations to rapidly respond to emerging threats and strengthen their cybersecurity posture.

## Key Features
- Automated Data Synchronization: Fetches and integrates CERT-IN threat intelligence data (STIX format) into MISP events.
- Data Extraction & Categorization: Automatically extracts relevant indicators, malware samples, attack patterns, tools, and threat actors from the incoming threat feeds.
- Event Creation & Enrichment: Creates MISP events enriched with the extracted threat intelligence data to facilitate comprehensive threat analysis and sharing.
- Scheduled Syncing: Supports configurable intervals for periodic synchronization, ensuring MISP stays updated with the latest threat intelligence.
- Customizable Integration: Easily configurable for different environments, including the integration of custom API keys and credentials.

## How It Works
1. Setup CERT-IN Credentials: Provide your CERT-IN username and password to fetch the relevant threat data.
2. MISP Configuration: Enter your MISP instance URL and the corresponding API key to facilitate communication between CERT-IN and MISP.
3. Automated Sync: Run the script to automatically fetch and push the CERT-IN threat data into your MISP platform, generating events populated with the latest indicators and analysis.
4. Scheduled Sync: Optionally, use cron jobs or task schedulers to automate the synchronization at regular intervals, ensuring continuous updates to your MISP instance.

## Installation

Follow the steps below to set up and run the `Threat-Intel-Feed-CERTIN-to-MISP` script:

1. Clone the repository:
   ```bash
   git clone https://github.com/jarvishdinocent/Threat-Intel-Feed-CERTIN-to-MISP.git
   cd Threat-Intel-Feed-CERTIN-to-MISP
  

2. Install Python:
   Ensure you have Python 3.6 or higher installed. You can check this with:
   ```bash
   python3 --version
   

3. Install the required Python packages:
   You can install the necessary libraries using pip:
   ```bash
   pip install -r requirements.txt


4. Set up Configuration:
   - Open the certin_to_misp.py file.
   - Replace the placeholder values for your CERT-IN URL, CERT-IN username, CERT-IN password, MISP URL, and MISP API key with your actual credentials.

5. Make the Python script executable:
   - chmod +x certin_to_misp.py

5. Run the Script:
   Run the script to fetch CERT-IN threat data and push it to MISP:
   ```bash
   - python3 certin_to_misp.py
   

6. Automated Sync (Optional):
   To run the script periodically (e.g., every hour), set up a cron job:
   ```bash
   crontab -e
   
   Add the following line to run the script every hour:
   ```bash
   0 * * * * /usr/bin/python3 /path/to/certin_to_misp.py
   

## License
This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
