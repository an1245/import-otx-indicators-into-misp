## v0.5

### Additions
* Added the ability to enrich the MISP attributes with tags that indicate which OTX pulses the attribute exists in

### Bug fixes
* Fixed bug in sighting logic.

### Upgrades
* Upgraded pymisp==2.5.33.2

## v0.4

### Additions
* Added the ability to automatically generate a new MISP event when AUTO_GENERATE_NEW_EVENT is set to True

## v0.3

### Additions
* Getting indicator details (get_indicator_details_full) will fail a maximum of 5 times and then add it anyway.
* Default VT_MALICIOUS_THRESHOLD updated to 2

### Upgrades
* Upgraded requests==2.33.1

## v0.2

### Additions
* Added support for Virustotal validation of OTX whitelisted entries
* Added progressing logging for indicators

### Upgrades
* Upgraded pymisp==2.5.33.1
* Upgraded requests==2.33.0

## v0.1

Initial Release