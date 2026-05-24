# ---- Import Config ----
from config import *

# ---- OTX Configuration ----
from OTXv2 import OTXv2
from OTXv2 import IndicatorTypes

# ---- Import Dependencies
from datetime import datetime, timedelta, timezone
import time
import requests.exceptions
import sys
import json

# ---- Import PyMISP ----
from pymisp import PyMISP, MISPEvent, MISPAttribute, MISPTag
from pymisp.exceptions import PyMISPError

# ---- Set continue on fail threshold ----
fail_continue_count = 5

# ---- Function to process config statements and return list of indicator types to import
def create_indicator_import_string():

    print("Building Indicator Import String")
    indicator_import_list= []

    # ---- Check if IMPORT_HOSTNAME exists and is true
    try:
        if IMPORT_HOSTNAME:
            print("Importing Hostname indicators from OTX")
            indicator_import_list.append(IndicatorTypes.HOSTNAME)
                      
    except NameError:
        print("IMPORT_HOSTNAME variable is not set in the configuration - check documentation.")

    
    # ---- Check if IMPORT_DOMAIN exists and is true
    try:
        if IMPORT_DOMAIN:
            print("Importing Domain indicators from OTX")
            indicator_import_list.append(IndicatorTypes.DOMAIN)
                      
    except NameError:
        print("IMPORT_DOMAIN variable is not set in the configuration - check documentation.")


    # ---- Check if IMPORT_IPV4 exists and is true
    try:
        if IMPORT_IPV4:
            print("Importing IPV4 indicators from OTX")
            indicator_import_list.append(IndicatorTypes.IPv4)
                      
    except NameError:
        print("IMPORT_IPV4 variable is not set in the configuration - check documentation.")


    # ---- Check if IMPORT_IPV6 exists and is true
    try:
        if IMPORT_IPV6:
            print("Importing IPV6 indicators from OTX")
            indicator_import_list.append(IndicatorTypes.IPv6)
                      
    except NameError:
        print("IMPORT_IPV6 variable is not set in the configuration - check documentation.")


    # ---- If no indicators are configured for import then import Domain and Hostname (backwards compatibility)
    if len(indicator_import_list) == 0:
        print("Importing Hostname and Domain indicators from OTX")
        indicator_import_list.append(IndicatorTypes.HOSTNAME)
        indicator_import_list.append(IndicatorTypes.DOMAIN)

    return indicator_import_list



# ---- Function to fetch indicator details from OTX
def fetch_indicator_details(otx, indicator_type,indicator_value, icount ):
    
    try:
        LOCAL_SKIP_WHITELIST_VALIDATION_AND_ENRICHMENT = SKIP_WHITELIST_VALIDATION_AND_ENRICHMENT
        LOCAL_SKIP_WHITELIST_VALIDATION_AND_ENRICHMENT_THRESHOLD = SKIP_WHITELIST_VALIDATION_AND_ENRICHMENT_THRESHOLD
    except NameError:
        LOCAL_SKIP_WHITELIST_VALIDATION_AND_ENRICHMENT = False
        LOCAL_SKIP_WHITELIST_VALIDATION_AND_ENRICHMENT_THRESHOLD = 100000
    
    indicator_details = ""
    fallback_json_string = '{"general": {"validation": [], "pulse_info": {"pulses": [] }}, "url_list": {"url_list": [{"date": "1970-01-01T00:00:00Z"}]}, "passive_dns": {"passive_dns": [{"last": "1970-01-01T00:00:00Z"}]}}'
    
    # ---- Get the indicator_details_full section for each indicator ----
    match indicator_type:
        case "IPv4":
            misp_type = "ip"
            if LOCAL_SKIP_WHITELIST_VALIDATION_AND_ENRICHMENT == False and icount < LOCAL_SKIP_WHITELIST_VALIDATION_AND_ENRICHMENT_THRESHOLD:
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
                        json_string = fallback_json_string
                        indicator_details = json.loads(json_string)
            else:
                # Create a JSON object for it.
                print("Skip whitelist validation:", end="")
                now = datetime.now().strftime("%Y-%m-%dT%H:%M:%S")
                json_string = fallback_json_string
                indicator_details = json.loads(json_string)

        case "IPv6":
            misp_type = "ip"
            if LOCAL_SKIP_WHITELIST_VALIDATION_AND_ENRICHMENT == False and icount < LOCAL_SKIP_WHITELIST_VALIDATION_AND_ENRICHMENT_THRESHOLD:
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
                    # Create a JSON object for it
                    now = datetime.now().strftime("%Y-%m-%dT%H:%M:%S")
                    json_string = fallback_json_string
                    indicator_details = json.loads(json_string)
            else:
                # Create a JSON object for it.
                print("Skip whitelist validation:", end="")
                now = datetime.now().strftime("%Y-%m-%dT%H:%M:%S")
                json_string = fallback_json_string
                indicator_details = json.loads(json_string)

        case "domain":
            misp_type = "domain"
            if LOCAL_SKIP_WHITELIST_VALIDATION_AND_ENRICHMENT == False and icount < LOCAL_SKIP_WHITELIST_VALIDATION_AND_ENRICHMENT_THRESHOLD:
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
                    json_string = fallback_json_string
                    indicator_details = json.loads(json_string)
            else:
                # Create a JSON object for it.
                print("Skip whitelist validation:", end="")
                now = datetime.now().strftime("%Y-%m-%dT%H:%M:%S")
                json_string = fallback_json_string
                indicator_details = json.loads(json_string)
        case "hostname":
            misp_type = "hostname"
            if LOCAL_SKIP_WHITELIST_VALIDATION_AND_ENRICHMENT == False and icount < LOCAL_SKIP_WHITELIST_VALIDATION_AND_ENRICHMENT_THRESHOLD:
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
                    json_string = fallback_json_string
                    indicator_details = json.loads(json_string)
            else:
                # Create a JSON object for it.
                print("Skip whitelist validation:", end="")
                now = datetime.now().strftime("%Y-%m-%dT%H:%M:%S")
                json_string = fallback_json_string
                indicator_details = json.loads(json_string)
        case _:
                return "",""

    return misp_type, indicator_details





def processIndicator(misp, event, misp_type, indicator_value, indicator_details, otx_latest_sighting, decay_unixtimestamp):
    # ---- Check if indicator exists already in MISP ----
		found = False
		for attribute in event.attributes:
			if attribute.value == indicator_value and attribute.type == misp_type:
				found = True

				misp_attribute_timestamp  = int(attribute.timestamp.timestamp())

				# ---- If the OTX timestamp is greater than the attribute timestamp then add a sighting
				if otx_latest_sighting > misp_attribute_timestamp:	
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
								print(" - adding missing tags", end="")
								for pulse in pulses:
									ptag = f"otx-pulse-name:{pulse.get('name')}"
									if not ptag in mtag_names:
										misp.tag(attribute.uuid, ptag)
										misp_tag = MISPTag()
										misp_tag.name = ptag
										print(".", end="")
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
								tag = f"otx-pulse-name:{pulse.get('name')}"
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