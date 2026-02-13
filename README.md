# Import Open Threat Exchange indicators into MISP

## Introduction
Open Threat Exchange (OTX) is a crowd-sourced computer-security platform. It allows the global community of threat researchers and security professionals to collaborative on research, contribute community-generated threat data, and automate the process of updating security infrastructure with threat data.

MISP Threat Sharing (MISP), is an open source threat intelligence platform that develops utilities and documentation for more effective threat intelligence and sharing indicators of compromise.

## What is get-indicators-from-otx.py?
I created the ***get-indicators-from-otx.py*** script to reduce the amount of false positive management I was having to do on my OTX threat feed data.  ***get-indicators-from-otx.py*** fetches domain/hostname (an optionally IPv4/IPv6) indicators from your subscribed OTX pulses and evaluates each indicator for false positives by:
1. Checking whether the indicator has been whitelisted in OTX. If it is, it does not add it into MISP
2. Calculating the most recent date/time (highest unix tz) from the following indicator metrics: 
    - The most recent date/time it was observed in passive_dns
    - The most recent date/time it was observed in url_list
    - The creation date/time of the indicator in the pulse
3. Checking whether the date/time (from above) is newer than the decay model lifetime date/time. If it is, it imports the indicator into MISP as a new attribute, or adds a sighting if the attribute exists in MISP already.

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

## Issues / Feedback
- I have done quite a lot of testing, but I am only human, so there may be bugs/errors.
- Please log bugs by logging an issue on GitHub
- Please give feedback - you can do that by starting a discussion on GitHub repo!
