# ---- PyMISP Configuration ----
MISP_URL = "{insert MISP url}"
MISP_API_KEY = "{insert MISP API key}"
MISP_VERIFY_CERT = False
EVENT_ID = {insert MISP Event ID}          # if AUTO_GENERATE_NEW_EVENT is set to False, indicators will be written to this EVENT_ID
AUTO_GENERATE_NEW_EVENT = False            # if AUTO_GENERATE_NEW_EVENT is set to True, a new event will be configured and indicators added to that event
ENRICH_EVENT_WITH_PULSE_NAMES = False      # if ENRICH_EVENT_WITH_PULSE_NAMES is set to True, an attribute tag will be created for each pulse name that the indicator exists in

# ---- OTX Configuration ----
OTX_API_KEY = "{insert OTX API key}" 

# ---- Import Configuration ----
IMPORT_DAYS=1                       # number of days to import.  works best if you import 1 day and run every day
DECAY_DAYS=120                      # don't import events that are older than x days ( should align with lifetime days in your decay model )

# ---- VirusTotal API Key ----
VT_API_KEY = "{insert VirusTotal API key}"

# ---- VirusTotal Malicious Score Limit ----
VT_MALICIOUS_THRESHOLD = 2          # if the malicious score is greater than this number, include it.