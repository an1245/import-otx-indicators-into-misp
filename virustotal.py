import requests.exceptions
import json

# ---- Import Config ----
from config import *

# ---- Disable Certificate Warnings ----
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ---- Get the virustotal domain score ----
def get_virustotal_domain_score(domain):

	# ---- Prepare the URL ----
	url = f"https://www.virustotal.com/api/v3/domains/{domain}"
	headers = { "accept": "application/json", "X-ApiKey": VT_API_KEY}

	# ---- Execute request and parse response ----
	try:
		response = requests.get(url, headers=headers, timeout=10)

		json_obj = response.json()

		# ---- Extract reputation score and return ----
		malicious_score = json_obj['data']['attributes']['last_analysis_stats']['malicious']

	except Exception as err:
		print("VirusTotal returned invalid response - check API key!", end="")
		return 1000000    # return a high score so it gets added into MISP

	return malicious_score

# ---- Get the virustotal ip score ----
def get_virustotal_ip_score(ip):

	# ---- Prepare the URL ----
	url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
	headers = { "accept": "application/json", "X-ApiKey": VT_API_KEY}

	# ---- Execute request and parse response ----
	try:
		response = requests.get(url, headers=headers, timeout=10)

		json_obj = response.json()

		# ---- Extract reputation score and return ----
		malicious_score = json_obj['data']['attributes']['last_analysis_stats']['malicious']

	except Exception as err:
		print("VirusTotal returned invalid response - check API key!", end="")
		return 1000000    # return a high score so it gets added into MISP

	return malicious_score

