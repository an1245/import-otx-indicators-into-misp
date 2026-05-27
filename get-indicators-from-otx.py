# ---- Datetime for time conversions ----
from datetime import datetime, timedelta, timezone
import time
import requests.exceptions
import sys
import json


# ---- Import PyMISP ----
from pymisp import PyMISP, MISPEvent, MISPAttribute, MISPTag
from pymisp.exceptions import PyMISPError

# ---- Import Config ----
from config import *

# ---- Import Util Functions ----
from util_functions import *

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
	print(f"Connecting to MISP Server {MISP_URL}")	
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
	
# ---- Check if AUTO_GENERATE_NEW_EVENT exists in config and if it doesn't them define it as False
try:
	LOCAL_AUTO_GENERATE_NEW_EVENT = AUTO_GENERATE_NEW_EVENT
except NameError:
	LOCAL_AUTO_GENERATE_NEW_EVENT = False

# ---- If LOCAL_AUTO_GENERATE_NEW_EVENT is False and EVENT_ID is 0 then there is a problem
if LOCAL_AUTO_GENERATE_NEW_EVENT == False and EVENT_ID == 0:
	print("Config.py entries AUTO_GENERATE_NEW_EVENT = False and EVENT_ID = 0 - incorrect config - check config - exiting")
	sys.exit(1)

# ---- Generate new event if AUTO_GENERATE_NEW_EVENT is True ----
try:
	if AUTO_GENERATE_NEW_EVENT:
		try:
			print("AUTO_GENERATE_NEW_EVENT was True - creating new event in MISP")	
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
	print(f"Fetching Event {EVENT_ID} from MISP")	
	event = misp.get_event(EVENT_ID, pythonify=True)
except Exception as e:
	print(f"Failed to get Event ID from MISP: Error: {e}")
	sys.exit(1)

# ---- Convert import DAYS into a timestamp
import_days_tz  = datetime.now(timezone.utc) - timedelta(days=IMPORT_DAYS)

# ---- Create import Types list ----
indicator_import_list = create_indicator_import_string()

# ---- Get new Domain/Hostname indicators from OTX ----
try:
	print(f"Fetching OTX indicators modified since {import_days_tz}")
	indicators = otx.get_all_indicators(indicator_types=indicator_import_list,modified_since=import_days_tz)
	indicator_count = otx.get_all_indicators(indicator_types=indicator_import_list,modified_since=import_days_tz)
except Exception as e:
	print("Caught error when trying to get indicators from OTX: ", e)
	sys.exit(1)

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
	
	# ---- Fetch indicator details from OTX
	misp_type, indicator_details = fetch_indicator_details(otx, indicator_type,indicator_value, icount )
	
	# ---- If the OTX indicator isn't an IP, Domain or Hostname, continue to next indicator
	if misp_type == "":
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
		elif misp_type == "ip":
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
		
		if misp_type == "domain" or misp_type == "hostname":
			
			# ---- Process a Domain/Hostname indicator as normal
			processIndicator(misp, event, misp_type, indicator_value, indicator_details, otx_latest_sighting, decay_unixtimestamp)
		
		elif misp_type == "ip":	
			
			# ---- Add ip-dst attribute type into MISP
			processIndicator(misp, event, "ip-dst", indicator_value, indicator_details, otx_latest_sighting, decay_unixtimestamp)


			# ---- If ADD_IP_SRC_FOR_EACH_OTX_IP == True in config.py, add ip-src attribute in MISP
			try:
				LOCAL_ADD_IP_SRC_FOR_EACH_OTX_IP = ADD_IP_SRC_FOR_EACH_OTX_IP
			except NameError:
				LOCAL_ADD_IP_SRC_FOR_EACH_OTX_IP = False

			if LOCAL_ADD_IP_SRC_FOR_EACH_OTX_IP == True:
				processIndicator(misp, event, "ip-src", indicator_value, indicator_details, otx_latest_sighting, decay_unixtimestamp)



# ---- Publish the event ----
print("Publishing Event")
try:
	misp.publish(EVENT_ID, alert=False)
except Exception as e:
	print(f"Failed to publish MISP event!")