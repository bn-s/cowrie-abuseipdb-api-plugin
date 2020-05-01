# AbuseIPDB 

## Alpha Version - Untested

### Usage

1. Copy abuseipdb.py into ~/cowrie/src/cowrie/output

2. Copy the configuration below into ~/cowrie/etc/cowrie.cfg.

    ```conf
    [output_abuseipdb]
    enabled = true
    tollerance_window = 360
    tollerance_attempts = 10
    rereport_after = 24
    dump_file = ${honeypot:state_path}/abuseipdb/aipdb.dump
    api_key =
    ```

3. Enter your AbuseIPDB API key and configure the tollerance and re-reporting settings as you whish.

### Configuration options

#### `tollerance_attempts`

The number of login attempts to be ovserved from an IP address before reporting it.

#### `tollerance_window`

The window of time (in minutes) in which login attempts will be counted. As an example, if `tollerance_attempts` is set to `2` and `tollerance_window` is set to one, an IP address making on login attempt every 61 seconds will go unreported. If, however, an IP address made two login attempts within a minute, it will be reported.

#### `rereport_after`

The number of hours to wait before making another report for the same IP address.

