# Import Open Threat Exchange indicators into MISP

## Introduction
Open Threat Exchange (OTX) is a crowd-sourced computer-security platform. It allows the global community of threat researchers and security professionals to collaborative on research, contribute community-generated threat data, and automate the process of updating security infrastructure with threat data.

MISP Threat Sharing (MISP), is an open source threat intelligence platform that develops utilities and documentation for more effective threat intelligence and sharing indicators of compromise.

## What is get-indicators-from-otx.py?
I created the ****get-indicators-from-otx.py*** script to reduce the amount of false positive management I was having to do on my OTX threat feed data.  ****get-indicators-from-otx.py*** fetches domain/hostname (an optionally IPv4/IPv6) indicators from your subscribe pulses in OTX and then uses a number of checks to determine if it is a false positive:
1. It checks whether the indicator has been whitelisted in OTX
2. It evaluates the most recent date/time (highest unix tz) from the following indicator metrics: 
    - The most recent date/time it was observed in passive_dns
    - The most recent date/time it was observed in url_list
    - The creation date/time of the indicator in the pulse
3. If the most recent date/time (from above) is newer than the decay model lifetime cutoff date, it either imports the indicator into MISP as a new attribute, or adds a sighting if the attribute exists already.

## How do i get started?
