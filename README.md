# Import Open Threat Exchange indicators into MISP

## Introduction
Open Threat Exchange (OTX) is a crowd-sourced computer-security platform. It allows the global community of threat researchers and security professionals to collaborative on research, contribute community-generated threat data, and automate the process of updating security infrastructure with threat data. The OTX Direct Connect API provides access to all Pulses that you have subscribed to in Open Threat Exchange.

MISP Threat Sharing (MISP) is an open source threat intelligence platform that develops utilities and documentation for more effective threat intelligence and sharing indicators of compromise.  With MISP, you can consume threat intelligence from other organizaions, store, organise and enrich it with contextual information, search for indicators and correlate them together, and push that threat intelligence out to firewalls, IDSs and endpoints. PyMISP is a Python library that provides an interface to access and automate a MISP (Malware Information Sharing Platform) instance via its REST API.

MISP users can use the OTX Direct Connect API to export indicators from OTX and import them into MISP using the PyMISP API.

## What is get-indicators-from-otx.py?
***get-indicators-from-otx.py*** allows you to ingest OTX threat intelligence into your MISP server in a way that reduces false positives and stale entries.
***get-indicators-from-otx.py*** fetches domain/hostname (and optionally IPv4/IPv6) indicators from your subscribed OTX pulses and evaluates each indicator as a false positive by:
1. Checking whether the indicator has been whitelisted in OTX - if it is whitelisted, it does not get added into MISP
2. Evaluating whether the indicator is stale, by ensuring one of the following date/times are ***newer*** than the MISP decay model lifetime: 
    - The most recent date/time observed in passive_dns
    - The most recent date/time observed in url_list
    - The creation date/time of the indicator in the pulse

If the indicator is deemed not to be whitelisted or stale, the script will add the indicator to the MISP Event specified by ***EVENT_ID***, with the ***to_ids*** flag set to true, and the indicator date set to the most recent of the three date/times evaluated above.  

After all indicators have been processed the script will publish the event.

## How do i get started?
1. Create a new Event in MISP and note it's Event ID (for use below)

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
vi get-indicators-from-otx.py
```

6. Configure your MISP url, MISP API Key, MISP Event ID and OTX API Key variables in the script
```
# ---- PyMISP Configuration ----
MISP_URL = "{insert MISP url}"
MISP_API_KEY = "{insert MISP API key}"
EVENT_ID = {insert MISP Event ID}

# ---- OTX Configuration ----
OTX_API_KEY = "{insert OTX API key}" 
```
7. Run the script
```
python3 ./get-indicators-from-otx.py
```

## Considerations
The script uses 1 API call per indicator to collect the indicator full details (get_indicator_details_full function).  Open Threat Exchange (OTX) limits API requests to 10k/hour when using and API key, returning a HTTP/429 response when you exceed this number. When the script receives an error, it will backoff for 2mins and retry again.

## Issues / Feedback
- I have done quite a lot of testing, but I am only human, so there may be bugs/errors.
- Please log bugs by logging an issue on GitHub
- Please give feedback - you can do that by starting a discussion on GitHub repo!
