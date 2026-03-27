# ---- Datetime for time conversions ----
from datetime import datetime, timedelta, timezone
import time
import requests.exceptions
import sys

# ---- Import PyMISP ----
from pymisp import PyMISP
from pymisp.exceptions import PyMISPError

# ---- Import Config ----
from config import *

# ---- Import VirusTotal
from virustotal import *

# ---- Disable Certificate Warnings ----
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ---- OTX Configuration ----
from OTXv2 import OTXv2
from OTXv2 import IndicatorTypes
otx = OTXv2(OTX_API_KEY)

# ---- Connect to MISP ----
try:
	misp = PyMISP(MISP_URL, MISP_API_KEY, MISP_VERIFY_CERT)
	
except requests.exceptions.ConnectionError as e:
	print(f"Failed to connect to MISP Server: (check URL): {e}")
	sys.exit(1)
except PyMISPError as e:
	print(f"Failed to connect to MISP Server: Authentication failed: {e}")
	sys.exit(1)
except Exception as e:
	print(f"Failed to connect to MISP Server: An unexpected error occurred: {e}")
	sys.exit(1)
	

# ---- Get event with attributes ----
try:
	event = misp.get_event(EVENT_ID, pythonify=True)
except Exception as e:
	print(f"Failed to get Event ID from MISP: Error: {e}")
	sys.exit(1)

# ---- Convert import DAYS into a timestamp
import_days_tz  = datetime.now(timezone.utc) - timedelta(days=IMPORT_DAYS)

# ---- Get new Domain/Hostname indicators from OTX ----
try:
	indicators = otx.get_all_indicators(indicator_types=[IndicatorTypes.DOMAIN,IndicatorTypes.HOSTNAME],modified_since=import_days_tz)
	indicator_count = otx.get_all_indicators(indicator_types=[IndicatorTypes.DOMAIN,IndicatorTypes.HOSTNAME],modified_since=import_days_tz)
except Exception as e:
	print("Caught error when trying to get indicators from OTX: ", e)
	traceback.print_exc()

icount = sum(1 for _ in indicator_count)
print(f"Processing {icount} indicators")

# ---- Enumerate the indicators and see if they exist already
count = 0
for indicator in indicators:
	count = count + 1
	print(".", end="")
	indicator_type = indicator.get("type")
	indicator_created = ""
	misp_type = ""
	otx_type = ""
	indicator_value = indicator.get("indicator","")
	print(f"Processing {count}/{icount}: {indicator_value} : ", end="")
	indicator_details = ""

	# ---- Get the indicator_details_full section for each indicator ----
	match indicator_type:
		case "IPv4":
			misp_type = "ip-dst"
			while True:
				try:
					print("fetching details (IPv4): ", end="")
					indicator_details = otx.get_indicator_details_full(IndicatorTypes.IPv4, indicator_value)
					break
				except Exception as e:
					print("Caught error: ", e, end="")
					print("Sleeping 2 mins: ", end="")
					time.sleep(120)
					print("Retrying: ", end="")
					continue
		case "IPv6":
			misp_type = "ip-dst"
			while True:
				try:
					print("fetching details (IPv6): ", end="")
					indicator_details = otx.get_indicator_details_full(IndicatorTypes.IPv6, indicator_value)
					break
				except Exception as e:
					print("Caught error: ", e, end="")
					print("Sleeping 2 mins:", end="")
					time.sleep(120)
					print("Retrying: ", end="")
					continue
		case "domain":
			misp_type = "domain"
			while True:
				try:
					print("fetching details (domain): ", end="")
					indicator_details = otx.get_indicator_details_full(IndicatorTypes.DOMAIN, indicator_value)
					break
				except Exception as e:
					print("Caught error: ", e, end="")
					print("Sleeping 2 mins:", end="")
					time.sleep(120)
					print("Retrying: ", end="")
					continue
		case "hostname":
			misp_type = "hostname"
			while True:
				try:
					print("fetching details (hostname): ", end="")
					indicator_details = otx.get_indicator_details_full(IndicatorTypes.HOSTNAME, indicator_value)
					break
				except Exception as e:
					print("Caught error: ", e, end="")
					print("Sleeping 2 mins:", end="")
					time.sleep(120)
					print("Retrying: ", end="")
					continue
		case _:
		        continue

	# ---- Check if the indicator is in a whitelist and if so bypass it ----
	validation = indicator_details.get("general")["validation"]
	is_whitelisted = any(
                        v.get("source") == "whitelist"
                        for v in validation
                )
	if is_whitelisted:

		print("In OTX whitelist - ", end="")

		# ---- Get reputation score from VirusTotal ----
		if misp_type == "domain" or misp_type == "hostname":
			vt_malicious_score = get_virustotal_domain_score(indicator_value)
		elif misp_type == "ip-dst":
			vt_malicious_score = get_virustotal_ip_score(indicator_value)
		else:
			vt_malicious_score = 0

		print("VT Malicious Score: ", vt_malicious_score , " and Threshold: ", VT_MALICIOUS_THRESHOLD, " - ", end="")

		# ---- Check if malicious score is greater than threshold and if it is, add it.
		if vt_malicious_score < VT_MALICIOUS_THRESHOLD:
			print("VT malicious score < threshold - skipping")
			continue
		else:
			print("VT malicious score >= threshold - adding - " , end="")

	# ---- Get the last_seen time from passive_dns  ----
	indicator_passive_dns = indicator_details.get("passive_dns")
	highest_unixtimestamp = 0
	for pdns in indicator_passive_dns["passive_dns"]:
		tz = int(datetime.fromisoformat(pdns.get("last").replace("Z", "+00:00")).timestamp())
		if tz > highest_unixtimestamp:
				highest_unixtimestamp = tz

	# ---- Get the last timestamp in the urls ---
	indicator_url_list = indicator_details.get("url_list")
	highest_url_list_date = 0
	for url in indicator_url_list["url_list"]:
		tz2 = int(datetime.fromisoformat(url.get("date").replace("Z", "+00:00")).timestamp())
		if tz2 > highest_url_list_date:
			highest_url_list_date = tz2

	# ---- Calculate the decay time so we aren't putting entries in that are stale ---
	decay_utc = datetime.now(timezone.utc) - timedelta(days=DECAY_DAYS)
	decay_unixtimestamp = decay_utc.timestamp()	

	# ---- Get the indicator creation time and see if it equals the MISP one
	indicator_created = indicator.get("created")
	otx_created_timestamp = int(datetime.fromisoformat(indicator_created.replace("Z", "+00:00")).timestamp())

	# ---- Sometimes passive_dns entries don't exist ----
	if highest_unixtimestamp  == 0:
                highest_unixtimestamp  = otx_created_timestamp

	# ---- Take the highest date from the event creation, passive_dns and url_list as the indicator date in MISP ----
	otx_latest_sighting = max(otx_created_timestamp,highest_unixtimestamp,highest_url_list_date)

	# ---- OK, process the indicator ---
	if indicator_value:

		# ---- Check if indicator exists already in MISP ----
		found = False
		for attribute in event.attributes:
			if attribute.value == indicator_value:
				found = True

				misp_attribute_timestamp  = int(attribute.timestamp.timestamp())

				# ---- If the OTX timestamp is greater than the attribute timestamp then add a sighting
				if otx_created_timestamp > otx_latest_sighting:
					print("Indicator exists - OTX timestamp was newer- adding sighting")
					try:
						response = misp.add_sighting({'id': attribute.id,'source': 'OTX Feed','type': '0'})
					except Exception as e:
   						print(f"Failed to create sighting - continuing")
				else:
					print("Indicator exists - OTX timestamp was older or the same - skipping")

		# ---- If the attribute doesn't exist then add it ----
		if not found:

			# ---- Only add indicator if it's greater than decay_unix_timestamp ----
			if otx_latest_sighting >=  decay_unixtimestamp:
				print("Indicator didn't exist - Adding attribute ")
				try:
					misp.add_attribute(EVENT_ID,{"type": misp_type,"value": indicator_value,"to_ids": True, "timestamp": otx_latest_sighting})
				except Exception as e:
   						print(f"Failed to create attribute - continuing")
			else:
				print("Indicator ts > decay_days ts - skipping ")

# ---- Publish the event ----
print("Publishing Event")
try:
	misp.publish(EVENT_ID, alert=False)
except Exception as e:
	print(f"Failed to publish MISP event!")