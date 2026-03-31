# ---- PyMISP Configuration ----
MISP_URL = "{insert MISP url}"
MISP_API_KEY = "{insert MISP API key}"
MISP_VERIFY_CERT = False
EVENT_ID = {insert MISP Event ID}

# ---- OTX Configuration ----
OTX_API_KEY = "{insert OTX API key}" 

# ---- Import Configuration ----
IMPORT_DAYS=1                       # number of days to import.  works best if you import 1 day and run every day (ideally 12 hours)
DECAY_DAYS=120                      # don't import events that are older than x days ( should align with lifetime days in your decay model )

# ---- VirusTotal API Key ----
VT_API_KEY = "{insert VirusTotal API key}"

# ---- VirusTotal Malicious Score Limit ----
VT_MALICIOUS_THRESHOLD = 2          # if the malicious score is greater than this number, include it.