# ---- Datetime for time conversions ----
from datetime import datetime, timedelta, timezone
import time

# ---- Import PyMISP ----
from pymisp import PyMISP

# ---- Import Config ----
from config import *

# ---- Disable Certificate Warnings ----
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ---- OTX Configuration ----
from OTXv2 import OTXv2
from OTXv2 import IndicatorTypes
otx = OTXv2(OTX_API_KEY)

# ---- Import Configuration ----
DAYS=1              # number of days to import.  works best if you import 1 day and run every day
DECAY_DAYS=120      # don't import events that are older than x days ( should align with lifetime days in your decay model )

# ---- Connect to MISP ----
misp = PyMISP(MISP_URL, MISP_API_KEY, MISP_VERIFY_CERT)

# ---- Get event with attributes ----
event = misp.get_event(EVENT_ID, pythonify=True)

# ---- Convert import DAYS into a timestamp
import_days_tz  = datetime.now(timezone.utc) - timedelta(days=DAYS)

# ---- Get new Domain/Hostname indicators from OTX ----
try:
	indicators = otx.get_all_indicators(indicator_types=[IndicatorTypes.DOMAIN,IndicatorTypes.HOSTNAME],modified_since=import_days_tz)
except Exception as e:
	print("Caught error when trying to get indicators from OTX: ", e)
	traceback.print_exc()

# ---- Enumerate the indicators and see if they exist already
for indicator in indicators:
	print(".", end="")
	indicator_type = indicator.get("type")
	indicator_created = ""
	misp_type = ""
	otx_type = ""
	indicator_value = indicator.get("indicator","")
	print("Processing indicator ", indicator_value, ": ", end="")
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
		print("Indicator was in whitelist - skipping")
		continue

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
					response = misp.add_sighting({'id': attribute.id,'source': 'OTX Feed','type': '0'})
				else:
					print("Indicator exists - OTX timestamp was older or the same - skipping")

		# ---- If the attribute doesn't exist then add it ----
		if not found:

			# ---- Only add indicator if it's greater than decay_unix_timestamp ----
			if otx_latest_sighting >=  decay_unixtimestamp:
				print("Indicator didn't exist - Adding attribute ")
				misp.add_attribute(EVENT_ID,{"type": misp_type,"value": indicator_value,"to_ids": True, "timestamp": otx_latest_sighting})
			else:
				print("Indicator ts > decay_days ts - skipping ")

# ---- Publish the event ----
print("Publishing Event")
misp.publish(EVENT_ID, alert=False)
