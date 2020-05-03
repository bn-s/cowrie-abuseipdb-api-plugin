# AbuseIPDB 

## Alpha Version - Untested

### Usage

1. Copy abuseipdb.py into ~/cowrie/src/cowrie/output

2. Copy the configuration below into ~/cowrie/etc/cowrie.cfg.

```
# /-- ABUSEIPDB --/
# Plugin for reporting login attempts via the AbuseIPDB API. Counts attempts
# made by an IP address within a sliding window of time and, if the number of
# attempts made exceeds the set tollerance for attempts, reports the IP 
# address.
#
# For example, with tollerance_window set to 1 and tollerance_attempts set to
# 2, an IP making a login attempt every 60 seconds will go unreported. If,
# however, this IP address made a login attempt less than a minute after a
# previous attempt, it would be reported.
#
# Setting tollerance_attempts to 1 or 0 renders the tollerance_window setting
# irrelevant. When set like so we also send the username used in the report
# comments.

[output_abuseipdb]
enabled = true

# This plugin keeps a record of what it's up to here so we can survive restarts
# and shutdowns without forgetting which IPs have been reported, which ones
# we're monitoring and whether we've been rate limited recently. Auto-saves
# every 10 minutes and when cowrie is stopped. If you are going to set a custom
# directory here, ensure that permissions are set so that only the user who
# runs Cowrie has write/execute permissions in the directory!

dump_path = ${honeypot:state_path}/abuseipdb

# tollerance_window is in minutes
tollerance_window = 180
tollerance_attempts = 10

# rereport_after is in hours. Accepts a float (number with decimal places) as
# input. There is a hardcoded minimum of 0.25 (15 minutes); any setting below
# this will default back to the minimum.

rereport_after = 6

# Insert your key here to unlock the gate to the AbuseIPDB API kingdom.

api_key =
# /-- END ABUSEIPDB --/
```
