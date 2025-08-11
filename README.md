## About

**check_sc_continent_snmp** - Icinga Plugin Script (Check Command). 

Monitoring plugin for Security Code Continent servers

Tested on:
- Debian GNU/Linux 12.11 (Bookworm) with Icinga r2.15.0-1, snmpget/snmpwalk 5.9.3, Continent-4 Security Node Server

Put here: /usr/lib/nagios/plugins/check_sc_continent_snmp.pl

PreReq: **snpmget** and  **snmpwalk** tools

## Usage


```
$ /usr/lib/nagios/plugins/check_sc_continent_snmp.pl [OPTIONS]

Options:
    --mode|-m
        Operation mode: 'sensors', 'cpu', 'memory', 'swap', 'storage',
        'system', 'cluster', 'firewall', or 'ips'

    --host|-H
        SNMP host address (IP or hostname)

    --community|-C
        SNMP community string (default: public)

    --verbose
        Enable verbose output with detailed information

    --show-cores (CPU mode only)
        Enable monitoring of individual CPU cores (thresholds optional)

    --alert-cores (CPU mode only, requires --show-cores)
        Make core status affect overall alert status. When enabled, any
        warning or critical status on a CPU core will elevate the overall
        status to at least that level.

    --warning-cpu (Sensors mode)
        Warning threshold for CPU temperature (Celsius)

    --critical-cpu (Sensors mode)
        Critical threshold for CPU temperature (Celsius)

    --warning-hdd (Sensors mode)
        Warning threshold for HDD temperature (Celsius)

    --critical-hdd (Sensors mode)
        Critical threshold for HDD temperature (Celsius)

    --warning-cpu-avg-1m (CPU mode)
        Warning threshold for average CPU load over 1 minute (percentage)

    --critical-cpu-avg-1m (CPU mode)
        Critical threshold for average CPU load over 1 minute (percentage)

    --warning-cpu-core-1m (CPU mode with --show-cores)
        Warning threshold for individual CPU cores over 1 minute
        (percentage)

    --critical-cpu-core-1m (CPU mode with --show-cores)
        Critical threshold for individual CPU cores over 1 minute
        (percentage)

    --warning-memory-usage-prct (Memory mode)
        Warning threshold for memory usage (percentage)

    --critical-memory-usage-prct (Memory mode)
        Critical threshold for memory usage (percentage)

    --warning-memory-usage-bytes (Memory mode)
        Warning threshold for memory usage in bytes

    --critical-memory-usage-bytes (Memory mode)
        Critical threshold for memory usage in bytes

    --warning-swap-usage-prct (Swap mode)
        Warning threshold for swap usage (percentage)

    --critical-swap-usage-prct (Swap mode)
        Critical threshold for swap usage (percentage)

    --no-swap-status (Swap mode)
        Status to return when no swap is configured (ok|warning|critical,
        default: ok)

    --warning-storage-usage-prct (Storage mode)
        Warning threshold for storage usage (percentage)

    --critical-storage-usage-prct (Storage mode)
        Critical threshold for storage usage (percentage)

    --warning-storage-usage-bytes (Storage mode)
        Warning threshold for storage usage in bytes

    --critical-storage-usage-bytes (Storage mode)
        Critical threshold for storage usage in bytes

    --filter-storage-regex (Storage mode)
        Regex filter for storage mount points (e.g. '^(sd|vg)' to select
        only sd* and vg* devices)

    --no-storage-status (Storage mode)
        Status to return when no storage is found (ok|warning|critical,
        default: ok)

    --warning-policy-last-install (System mode)
        Warning threshold for last policy install time (seconds)

    --critical-policy-last-install (System mode)
        Critical threshold for last policy install time (seconds)

    --warning-conntrack-prct (System mode)
        Warning threshold for conntrack usage (percentage)

    --critical-conntrack-prct (System mode)
        Critical threshold for conntrack usage (percentage)

    --warning-cluster-node-state (Cluster mode)
        Warning threshold for cluster node state (active|standby|unknown,
        multiple values separated by semicolon)

    --critical-cluster-node-state (Cluster mode)
        Critical threshold for cluster node state (active|standby|unknown,
        multiple values separated by semicolon)

    --warning-cluster-node-role (Cluster mode)
        Warning threshold for cluster node role (primary|reserved|unknown,
        multiple values separated by semicolon)

    --critical-cluster-node-role (Cluster mode)
        Critical threshold for cluster node role (primary|reserved|unknown,
        multiple values separated by semicolon)

    --warning-cluster-node-status (Cluster mode)
        Warning threshold for cluster node status (ok|attention|ok, not
        ready|problem|down|unavailable|busy, multiple values separated by
        semicolon)

    --critical-cluster-node-status (Cluster mode)
        Critical threshold for cluster node status (ok|attention|ok, not
        ready|problem|down|unavailable|busy, multiple values separated by
        semicolon)

    --no-link-partner-node (Cluster mode)
        Status to return when no link to partner node (ok|warning|critical,
        default: critical)

    --firewall-not-running (Firewall mode)
        Status to return when firewall is not running (ok|warning|critical,
        default: critical)

    --ips-not-running (IPS mode)
        Status to return when IPS is not running (ok|warning|critical,
        default: warning)

    --snmp-version|-v
        SNMP version (1, 2c, or 3, default: 2c)

    --snmp-port|-p
        SNMP port (default: 161)

    --username|-u
        SNMPv3 username (required for SNMPv3)

    --auth-password|-A
        SNMPv3 authentication password

    --auth-protocol|-a
        SNMPv3 authentication protocol (MD5|SHA, default: SHA)

    --priv-password|-P
        SNMPv3 privacy password

    --priv-protocol|-r
        SNMPv3 privacy protocol (DES|AES, default: AES)

    --timeout|-t
        SNMP timeout in seconds (default: 10)

    --help|-h
        Print this help message

    --version|-V
        Print plugin version


```
Examples for all modes:

```
      # Sensors mode
      ./check_sc_continent_snmp.pl --mode sensors \
        --snmp-version 3 --username 'myuser' \
        --auth-password 'pwd1' --auth-protocol 'MD5'  --priv-protocol 'AES' --priv-password 'pwd2' \
        --host 'Server01' \
        --warning-cpu=70 --critical-cpu=80 \
        --warning-hdd=50 --critical-hdd=60

      # CPU average load check
      ./check_sc_continent_snmp.pl --mode cpu -H 192.168.1.100 \
        --warning-cpu-avg-1m=80 --critical-cpu-avg-1m=90

      # CPU average and core load check with core alerts
      ./check_sc_continent_snmp.pl --mode cpu -H 192.168.1.100 \
        --warning-cpu-avg-1m=80 --critical-cpu-avg-1m=90 \
        --show-cores \
        --warning-cpu-core-1m=90 --critical-cpu-core-1m=95 \
        --alert-cores \
        --verbose

      # Memory usage check
      ./check_sc_continent_snmp.pl --mode memory -H 192.168.1.100 \
        --warning-memory-usage-prct=80 --critical-memory-usage-prct=90

      # Swap usage check
      ./check_sc_continent_snmp.pl --mode swap -H 192.168.1.100 \
        --warning-swap-usage-prct=50 --critical-swap-usage-prct=70 \
        --no-swap-status=warning

      # Storage usage check
      ./check_sc_continent_snmp.pl --mode storage -H 192.168.1.100 \
        --warning-storage-usage-prct=80 --critical-storage-usage-prct=90 \
        --filter-storage-regex='^(sd|vg)' \
        --verbose

      # System status check
      ./check_sc_continent_snmp.pl --mode system -H 192.168.1.100 \
        --warning-policy-last-install=86400 --critical-policy-last-install=172800 \
        --warning-conntrack-prct=80 --critical-conntrack-prct=90 \
        --verbose

      # Cluster status check
      ./check_sc_continent_snmp.pl --mode cluster -H 192.168.1.100 \
        --warning-cluster-node-state="standby" --critical-cluster-node-state="unknown" \
        --warning-cluster-node-role="reserved" --critical-cluster-node-role="unknown" \
        --warning-cluster-node-status="attention;ok, not ready" \
        --critical-cluster-node-status="problem;down;unavailable;busy" \
        --no-link-partner-node=warning \
        --verbose

      # Firewall state check
      ./check_sc_continent_snmp.pl --mode firewall -H 192.168.1.100 \
        --firewall-not-running=critical

      # IPS state check
      ./check_sc_continent_snmp.pl --mode ips -H 192.168.1.100 \
        --ips-not-running=warning


```
