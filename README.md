# Import Open Threat Exchange indicators into MISP

## Introduction
Open Threat Exchange (OTX) is a crowd-sourced computer-security platform. It allows the global community of threat researchers and security professionals to collaborative on research, contribute community-generated threat data, and automate the process of updating security infrastructure with threat data. The OTX Direct Connect API provides access to all Pulses that you have subscribed to in Open Threat Exchange.

MISP Threat Sharing (MISP) is an open source threat intelligence platform that develops utilities and documentation for more effective threat intelligence and sharing indicators of compromise.  With MISP, you can consume threat intelligence from other organizaions, store, organise and enrich it with contextual information, search for indicators and correlate them together, and push that threat intelligence out to firewalls, IDSs and endpoints. PyMISP is a Python library that provides an interface to access and automate a MISP (Malware Information Sharing Platform) instance via its REST API.

MISP users can use the OTX Direct Connect API to export indicators from OTX and import them into MISP using the PyMISP API.

## What is get-indicators-from-otx.py?
***get-indicators-from-otx.py*** allows you to ingest OTX threat intelligence into your MISP server in a way that reduces false positives and stale entries.
***get-indicators-from-otx.py*** fetches domain/hostname (and optionally IPv4/IPv6) indicators from your subscribed OTX pulses and evaluates each indicator as a false positive by:
1. Checking whether the domain has been whitelisted in OTX
2. If domain is whitelisted in OTX, it uses the VirusTotal API to get the Malicious score for this domain/hostname/IP from VirusTotal.  If the Malicious score is greater than ***VT_MALICIOUS_THRESHOLD*** it moves onto the stale entry checking below.
3. Evaluating whether the indicator is stale, by ensuring one of the following date/times are ***newer*** than the MISP decay model lifetime: 
    - The most recent date/time observed in passive_dns
    - The most recent date/time observed in url_list
    - The creation date/time of the indicator in the pulse

If the indicator is deemed not to be whitelisted or stale, the script will add the indicator to the MISP Event specified by ***EVENT_ID***, with the ***to_ids*** flag set to true, and the indicator date set to the most recent of the three date/times evaluated above.  If you want to create a new MISP event each time, you can set ***AUTO_GENERATE_NEW_EVENT*** to True in ***config.py***.  This will create a new event and add all the indicators to that event.

After all indicators have been processed the script will publish the event.

## How do i get started?
1. If not using AUTO_GENERATE_NEW_EVENT, create a new Event in MISP and note it's Event ID (for use below)

2. Download code from Git
```
git clone https://github.com/an1245/import-otx-indicators-into-misp
```

3. Change into directory 
```
cd import-otx-indicators-into-misp
```

4. Install the pre-requisites
```
pip install -r requirements.txt
```

5. Edit the script
```
vi config.py
```

6. Configure your MISP url, MISP API Key, MISP Event ID, OTX API Key and VirusTotal API Key in ***config.py***.   Define your import and Decay Days variables.
```
# ---- PyMISP Configuration ----
MISP_URL = "{insert MISP url}"
MISP_API_KEY = "{insert MISP API key}"
MISP_VERIFY_CERT = False
EVENT_ID = {insert MISP Event ID}          # if AUTO_GENERATE_NEW_EVENT is set to False, indicators will be written to this EVENT_ID
AUTO_GENERATE_NEW_EVENT = False            # if AUTO_GENERATE_NEW_EVENT is set to True, a new event will be created and indicators added to that

# ---- OTX Configuration ----
OTX_API_KEY = "{insert OTX API key}" 

# ---- Import Configuration ----
IMPORT_DAYS=1                   # number of days to import.  works best if you import 1 day and run every day 
DECAY_DAYS=120                  # don't import events that are older than x days ( should align with lifetime days in your decay model )

# ---- VirusTotal API Key ----
VT_API_KEY = "{insert VirusTotal API key}"

# ---- VirusTotal Malicious Score Limit ----
VT_MALICIOUS_THRESHOLD = 2      # if the malicious score is greater than this number, include it.
```
7. Run the script
```
python3 ./get-indicators-from-otx.py
```

## Considerations
The script uses 1 API call per indicator to collect the indicator full details (get_indicator_details_full function).  Open Threat Exchange (OTX) limits API requests to 10k/hour when using and API key, returning a HTTP/429 response when you exceed this number. When the script receives an error, it will backoff for 2mins and retry again. If it fails to receive the indicator full details (get_indicator_details_full function) after five attempts, it will add the indicator and move on to the next one.

## Issues / Feedback
- I have done quite a lot of testing, but I am only human, so there may be bugs/errors.
- Please log bugs by logging an issue on GitHub
- Please give feedback - you can do that by starting a discussion on GitHub repo!
