# ---- Datetime for time conversions ----
from datetime import datetime, timedelta, timezone
import time
import requests.exceptions
import sys

# ---- Import PyMISP ----
from pymisp import PyMISP, MISPEvent, MISPAttribute, MISPTag
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

# ---- Set continue on fail threshold ----
fail_continue_count = 5

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
	

# ---- Generate new event if AUTO_GENERATE_NEW_EVENT is True ----
try:
	if AUTO_GENERATE_NEW_EVENT:
		try:
			event = MISPEvent()
			event.info = "Imported indicators from LevelBlue Open Threat Exchange "
			event.distribution = 0  		# Your organization only
			event.threat_level_id = 2  		# Medium
			event.analysis = 0  			# Initial
			new_event = misp.add_event(event, pythonify=True)
			EVENT_ID = new_event.id
			
		except Exception as e:
			print(f"Failed creating new Event in MISP: Error: {e}")
			sys.exit(1)
	else:
		if not isinstance(EVENT_ID, (int)):
			print(f"EVENT ID is not a number and AUTO_GENERATE_NEW_EVENT is set to False.  Check Config")
			sys.exit(1)
except NameError:
	print("AUTO_GENERATE_NEW_EVENT variable is not set in the configuration - check documentation.")


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
print(f"Processing {icount} OTX indicators into MISP Event ID: {EVENT_ID}")

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
			fail_count = 0
			while fail_count < fail_continue_count:
				try:
					print("fetching details (IPv4): ", end="")
					indicator_details = otx.get_indicator_details_full(IndicatorTypes.IPv4, indicator_value)
					break
				except Exception as e:
					fail_count = fail_count + 1
					print("Caught error: ", e, end="")
					print("Sleeping 2 mins: ", end="")
					time.sleep(120)
					print("Retrying(", fail_count,"):", end="")
					continue
			else:
				print("Failed to collect indicator details - Creating JSON Object for entry:", end="")
				# Create a JSON object for it.
				now = datetime.now().strftime("%Y-%m-%dT%H:%M:%S")
				json_string = '{"general": {"validation": []}, "url_list": {"url_list": [{"date": "' + str(now) + '"}]}, "passive_dns": {"passive_dns": [{"last": "' + str(now) + '"}]}}'
				indicator_details = json.loads(json_string)

		case "IPv6":
			misp_type = "ip-dst"
			fail_count = 0
			while fail_count < fail_continue_count:				
				try:
					print("fetching details (IPv6): ", end="")
					indicator_details = otx.get_indicator_details_full(IndicatorTypes.IPv6, indicator_value)
					break
				except Exception as e:
					fail_count = fail_count + 1
					print("Caught error: ", e, end="")
					print("Sleeping 2 mins:", end="")
					time.sleep(120)
					print("Retrying(", fail_count,"):", end="")
					continue
			else:
				print("Failed to collect indicator details - Creating JSON Object for entry:", end="")
				# Create a JSON object for it.
				now = datetime.now().strftime("%Y-%m-%dT%H:%M:%S")
				json_string = '{"general": {"validation": []}, "url_list": {"url_list": [{"date": "' + str(now) + '"}]}, "passive_dns": {"passive_dns": [{"last": "' + str(now) + '"}]}}'
				indicator_details = json.loads(json_string)

		case "domain":
			misp_type = "domain"
			fail_count = 0
			while fail_count < fail_continue_count:
				try:
					print("fetching details (domain): ", end="")
					indicator_details = otx.get_indicator_details_full(IndicatorTypes.DOMAIN, indicator_value)
					break
				except Exception as e:
					fail_count = fail_count + 1
					print("Caught error: ", e, end="")
					print("Sleeping 2 mins:", end="")
					time.sleep(120)
					print("Retrying(", fail_count,"):", end="")
					continue
			else:
				print("Failed to collect indicator details - Creating JSON Object for entry:", end="")
				# Create a JSON object for it.
				now = datetime.now().strftime("%Y-%m-%dT%H:%M:%S")
				json_string = '{"general": {"validation": []}, "url_list": {"url_list": [{"date": "' + str(now) + '"}]}, "passive_dns": {"passive_dns": [{"last": "' + str(now) + '"}]}}'
				indicator_details = json.loads(json_string)

		case "hostname":
			misp_type = "hostname"
			fail_count = 0
			while fail_count < fail_continue_count:
				try:
					print("fetching details (hostname): ", end="")
					indicator_details = otx.get_indicator_details_full(IndicatorTypes.HOSTNAME, indicator_value)
					break
				except Exception as e:
					fail_count = fail_count + 1
					print("Caught error: ", e, end="")
					print("Sleeping 2 mins:", end="")
					time.sleep(120)
					print("Retrying(", fail_count,"):", end="")
					continue
			else:
				print("Failed to collect indicator details - Creating JSON Object for entry:", end="")
				# Create a JSON object for it.
				now = datetime.now().strftime("%Y-%m-%dT%H:%M:%S")
				json_string = '{"general": {"validation": []}, "url_list": {"url_list": [{"date": "' + str(now) + '"}]}, "passive_dns": {"passive_dns": [{"last": "' + str(now) + '"}]}}'
				indicator_details = json.loads(json_string)

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
					print("Indicator exists - OTX timestamp was newer- adding sighting", end="")
					try:
						response = misp.add_sighting({'id': attribute.id,'source': 'OTX Feed','type': '0'})
						
						try: 
							if ENRICH_EVENT_WITH_PULSE_NAMES:
								# ---- Enumerate MISP tags into a list
								mtag_names = []
								mtags = attribute.get('Tag', [])
								for mtag in mtags:
									mtag_names.append(mtag['name'])
								
								# ---- Enumerate pulse tags and see if they exist in the list
								pulses = indicator_details.get("general")["pulse_info"]["pulses"]
								for pulse in pulses:
									ptag = f"otx-pulse-name:{pulse.get("name")}"
									if not ptag in mtag_names:
										misp.tag(attribute.id, ptag)
										
										misp_tag = MISPTag()
										misp_tag.name = ptag
										print(" - adding missing tags", end="")
										attribute.tags.append(misp_tag)
						except NameError:
							pass
						except:
							print(" - failed to create tags", end="")
						
					except Exception as e:
   						print(f"Failed to create sighting - continuing", end="")
					
					print()
				
				else:
					print("Indicator exists - OTX timestamp was older or the same - skipping")

		# ---- If the attribute doesn't exist then add it ----
		if not found:

			# ---- Only add indicator if it's greater than decay_unix_timestamp ----
			if otx_latest_sighting >=  decay_unixtimestamp:
				print("Indicator didn't exist - Adding attribute ")
				try:
					misp_attribute = MISPAttribute()
					misp_attribute.type = misp_type
					misp_attribute.value = indicator_value
					misp_attribute.to_ids = True
					misp_attribute.timestamp = datetime.fromtimestamp(otx_latest_sighting)
									
					try: 
						if ENRICH_EVENT_WITH_PULSE_NAMES:

							# Put pulse names into tags
							pulses = indicator_details.get("general")["pulse_info"]["pulses"]
							for pulse in pulses:
								tag = f"otx-pulse-name:{pulse.get("name")}"
								misp_attribute.add_tag(tag)
					
					except NameError:
						pass
					
					misp.add_attribute(EVENT_ID, misp_attribute)
					
					# Add to event.attributes list so that if we find a duplicate entry in this run, we make a sighting
					event.attributes.append(misp_attribute)

				except Exception as e:
   						print(f"Failed to create attribute - continuing", e)
			else:
				print("Indicator ts > decay_days ts - skipping ")

# ---- Publish the event ----
print("Publishing Event")
try:
	misp.publish(EVENT_ID, alert=False)
except Exception as e:
	print(f"Failed to publish MISP event!")