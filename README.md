# Import Open Threat Exchange indicators into MISP

## Introduction
Open Threat Exchange (OTX) is a crowd-sourced computer-security platform. It allows the global community of threat researchers and security professionals to collaborative on research, contribute community-generated threat data, and automate the process of updating security infrastructure with threat data.

MISP Threat Sharing (MISP) is an open source threat intelligence platform that develops utilities and documentation for more effective threat intelligence and sharing indicators of compromise.  With MISP, you can consume threat intelligence from other organizaions, store, organise and enrich it with contextual information, search for indicators and correlate them together, and push that threat intelligence out to firewalls, IDSs and endpoints.

## What is get-indicators-from-otx.py?
***get-indicators-from-otx.py*** allows you to ingest OTX threat intelligence into your MISP server in a way that reduces false positives.
***get-indicators-from-otx.py*** fetches domain/hostname (an optionally IPv4/IPv6) indicators from your subscribed OTX pulses and evaluates each indicator as a false positive by:
1. Checking whether the indicator has been whitelisted in OTX - if it has, it does not add it into MISP
2. Finding the most recent observation date/time of the indicator by evaluating: 
    - The most recent date/time observed in passive_dns
    - The most recent date/time observed in url_list
    - The creation date/time of the indicator in the pulse
3. Then checking if the most recent observation date/time (from above) is ***newer*** than the MISP decay model lifetime date/time - if it is, it imports the indicator into MISP as a new attribute, or adds a sighting if the attribute exists in MISP already.

Evaluating the most recent observation date/time of an indicator helps to eliminate stale indicator entries which can lead to false positives.  This can occur where a new indicator is added to an old OTX pulse.

## How do i get started?
1. Download code from Git
```
git clone https://github.com/an1245/import-otx-indicators-into-misp
```

2. Change into directory and set executable bit
```
cd import-otx-indicators-into-misp
chmod 0700 get-indicators-from-otx.py
```

3. Install the pre-requisites
```
pip install -r requirements.txt
```

4. Edit the script
```
vi get-indicators-from-otx.py
```
5. Configure your MISP url, MISP API Key, MISP Event ID and OTX API Key variables in the script
```
# ---- PyMISP Configuration ----
MISP_URL = "{insert MISP url}"
MISP_API_KEY = "{insert MISP API key}"
EVENT_ID = {insert MISP Event ID}

# ---- OTX Configuration ----
OTX_API_KEY = "{insert OTX API key}" 
```
5. Run the script
```
./get-indicators-from-otx.py
```

## Considerations
Open Threat Exchange (OTX) limits API requests to 10k/hour when using and API key, returning a HTTP/429 response when you exceed this number. When the script receives an error, it will backoff for 2mins and retry again.

## Issues / Feedback
- I have done quite a lot of testing, but I am only human, so there may be bugs/errors.
- Please log bugs by logging an issue on GitHub
- Please give feedback - you can do that by starting a discussion on GitHub repo!
