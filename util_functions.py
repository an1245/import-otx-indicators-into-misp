# ---- Import Config ----
from config import *

# ---- OTX Configuration ----
from OTXv2 import OTXv2
from OTXv2 import IndicatorTypes

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