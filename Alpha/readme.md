# AbuseIPDB 

## Alpha Version - Untested

### Usage
1. Copy the configuration below into ~/cowrie/etc/cowrie.cfg.

    ```conf
    [output_abuseipdb]
    enabled = true
    tollerance_window = 30
    tollerance_attempts = 10
    rereport_after = 24
    dump_file = ${honeypot:state_path}/abuseipdb/aipdb.dump
    api_key = 
    ```

2. Create the following directory ~/cowrie/var/lib/cowrie/abuseipdb

3. Copy abuseipdb.py into ~/cowrie/src/cowrie/output
