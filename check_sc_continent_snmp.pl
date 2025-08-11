#!/usr/bin/perl
# =============================
# check_sc_continent_snmp.pl
# Monitoring plugin for Security Code Continent servers
# Version: 1.8.0
# History:
#   1.8.0 [2025-08-11] Added IPS monitoring mode
# =============================

use strict;
use warnings;
use Getopt::Long;
use Pod::Usage;

# ========== CONSTANTS ==========
my $VERSION = "1.8.0";
my $SNMPGET = '/usr/bin/snmpget';
my $SNMPWALK = '/usr/bin/snmpwalk';

# ========== OID DEFINITIONS ==========
my %OIDS = (
    # Sensors mode
    tempCPU => '1.3.6.1.4.1.34849.1.1.2.6.1.0',
    tempHDD => '1.3.6.1.4.1.34849.1.1.2.6.5.0',
    
    # CPU mode
    cpuLoadAvg1Min  => '1.3.6.1.4.1.34849.1.1.2.1.1.1.0',
    coreIndex       => '1.3.6.1.4.1.34849.1.1.2.1.3.1.1',
    coreLoadAvg1Min => '1.3.6.1.4.1.34849.1.1.2.1.3.1.2',
    
    # Memory mode
    ramTotalBytes   => '1.3.6.1.4.1.34849.1.1.2.2.1.0',
    ramUsedBytes    => '1.3.6.1.4.1.34849.1.1.2.2.2.0',
    ramUsedPercents => '1.3.6.1.4.1.34849.1.1.2.2.3.0',
    
    # Swap mode
    swapTotalBytes   => '1.3.6.1.4.1.34849.1.1.2.3.1.0',
    swapUsedBytes    => '1.3.6.1.4.1.34849.1.1.2.3.2.0',
    swapUsedPercents => '1.3.6.1.4.1.34849.1.1.2.3.3.0',
    
    # Storage mode
    fsIndex        => '1.3.6.1.4.1.34849.1.1.2.4.1.1.1',
    fsMountPoint   => '1.3.6.1.4.1.34849.1.1.2.4.1.1.2',
    fsUsedBytes    => '1.3.6.1.4.1.34849.1.1.2.4.1.1.3',
    fsUsedPercents => '1.3.6.1.4.1.34849.1.1.2.4.1.1.4',
    fsFreeBytes    => '1.3.6.1.4.1.34849.1.1.2.4.1.1.5',
    
    # System mode
    continentVersion      => '1.3.6.1.4.1.34849.1.1.1.3.1.0',
    nodeUpTime            => '1.3.6.1.4.1.34849.1.1.1.3.2.0',
    IPSVersion            => '1.3.6.1.4.1.34849.1.1.1.3.3.0',
    KasperskyFeedsVersion => '1.3.6.1.4.1.34849.1.1.1.3.4.0',
    KasperskyHashVersion  => '1.3.6.1.4.1.34849.1.1.1.3.5.0',
    UserHashVersion       => '1.3.6.1.4.1.34849.1.1.1.3.6.0',
    GeoIPVersion          => '1.3.6.1.4.1.34849.1.1.1.3.7.0',
    SkyDNSVersion         => '1.3.6.1.4.1.34849.1.1.1.3.8.0',
    lastPolicyInstall     => '1.3.6.1.4.1.34849.1.1.1.3.9.0',
    maxConntrack          => '1.3.6.1.4.1.34849.1.1.1.3.10.0',
    countConntrack        => '1.3.6.1.4.1.34849.1.1.1.3.11.0',
    
    # Cluster mode
    clusterReservStateOn  => '1.3.6.1.4.1.34849.1.1.1.6.1.0',
    clusterReservStateRole => '1.3.6.1.4.1.34849.1.1.1.6.2.0',
    clusterReservLink     => '1.3.6.1.4.1.34849.1.1.1.6.3.0',
    clusterReservStatus   => '1.3.6.1.4.1.34849.1.1.1.6.4.0',
    
    # Firewall mode
    fwState => '1.3.6.1.4.1.34849.1.1.1.2.1.0',
    
    # IPS mode
    ipsComponentState => '1.3.6.1.4.1.34849.1.1.1.1.2.0',
);

# ========== NAGIOS STATUS CODES ==========
use constant {
    OK       => 0,
    WARNING  => 1,
    CRITICAL => 2,
    UNKNOWN  => 3,
};

# Status labels for output
my %STATUS_BY_CODE = (
    0 => 'OK',
    1 => 'WARNING',
    2 => 'CRITICAL',
    3 => 'UNKNOWN',
);

# ========== MAIN ==========
my $mode;
my $host;
my $community = 'public';
my $help;
my $version;
my $verbose;
my $snmp_version = '2c';
my $snmp_port = 161;
my $snmp_username;
my $snmp_auth_password;
my $snmp_auth_protocol = 'SHA';
my $snmp_priv_password;
my $snmp_priv_protocol = 'AES';
my $timeout = 10;

# Mode-specific options
my ($warning_cpu, $critical_cpu, $warning_hdd, $critical_hdd);       # sensors
my ($warning_cpu_avg_1m, $critical_cpu_avg_1m);                      # cpu
my ($warning_cpu_core_1m, $critical_cpu_core_1m);                    # cpu
my $show_cores = 0;                                                  # cpu
my $alert_cores = 0;                                                 # cpu
my ($warning_memory_usage_prct, $critical_memory_usage_prct);        # memory
my ($warning_memory_usage_bytes, $critical_memory_usage_bytes);      # memory
my ($warning_swap_usage_prct, $critical_swap_usage_prct);            # swap
my $no_swap_status = 'ok';                                           # swap
my ($warning_storage_usage_prct, $critical_storage_usage_prct);      # storage
my ($warning_storage_usage_bytes, $critical_storage_usage_bytes);    # storage
my $filter_storage_regex;                                            # storage
my $no_storage_status = 'ok';                                        # storage
my ($warning_policy_last_install, $critical_policy_last_install);    # system
my ($warning_conntrack_prct, $critical_conntrack_prct);              # system
my ($warning_cluster_node_state, $critical_cluster_node_state);      # cluster
my ($warning_cluster_node_role, $critical_cluster_node_role);        # cluster
my ($warning_cluster_node_status, $critical_cluster_node_status);    # cluster
my $no_link_partner_node = 'critical';                               # cluster
my $firewall_not_running_status = 'critical';                        # firewall
my $ips_not_running_status = 'warning';                              # ips

# Handle version and help immediately
if (grep { /^-V$|^--version$/ } @ARGV) {
    print "check_sc_continent_snmp.pl v$VERSION\n";
    exit OK;
}

if (grep { /^-h$|^--help$/ } @ARGV) {
    pod2usage(1);
}

# Parse command-line options
GetOptions(
    'mode|m=s'           => \$mode,
    'host|H=s'           => \$host,
    'community|C:s'      => \$community,
    'help|h'             => \$help,
    'version|V'          => \$version,
    'verbose'            => \$verbose,
    'snmp-version|v:s'   => \$snmp_version,
    'snmp-port|p:i'      => \$snmp_port,
    'username|u:s'       => \$snmp_username,
    'auth-password|A:s'  => \$snmp_auth_password,
    'auth-protocol|a:s'  => \$snmp_auth_protocol,
    'priv-password|P:s'  => \$snmp_priv_password,
    'priv-protocol|r:s'  => \$snmp_priv_protocol,
    'timeout|t:i'        => \$timeout,
    
    # Sensors mode options
    'warning-cpu|W=s'    => \$warning_cpu,
    'critical-cpu|K=s'   => \$critical_cpu,
    'warning-hdd|w=s'    => \$warning_hdd,
    'critical-hdd|k=s'   => \$critical_hdd,
    
    # CPU mode options
    'warning-cpu-avg-1m=s'   => \$warning_cpu_avg_1m,
    'critical-cpu-avg-1m=s'  => \$critical_cpu_avg_1m,
    'warning-cpu-core-1m=s'  => \$warning_cpu_core_1m,
    'critical-cpu-core-1m=s' => \$critical_cpu_core_1m,
    'show-cores'             => \$show_cores,
    'alert-cores'            => \$alert_cores,
    
    # Memory mode options
    'warning-memory-usage-prct=s'  => \$warning_memory_usage_prct,
    'critical-memory-usage-prct=s' => \$critical_memory_usage_prct,
    'warning-memory-usage-bytes=s' => \$warning_memory_usage_bytes,
    'critical-memory-usage-bytes=s' => \$critical_memory_usage_bytes,
    
    # Swap mode options
    'warning-swap-usage-prct=s'  => \$warning_swap_usage_prct,
    'critical-swap-usage-prct=s' => \$critical_swap_usage_prct,
    'no-swap-status=s'           => \$no_swap_status,
    
    # Storage mode options
    'warning-storage-usage-prct=s'  => \$warning_storage_usage_prct,
    'critical-storage-usage-prct=s' => \$critical_storage_usage_prct,
    'warning-storage-usage-bytes=s' => \$warning_storage_usage_bytes,
    'critical-storage-usage-bytes=s' => \$critical_storage_usage_bytes,
    'filter-storage-regex=s'        => \$filter_storage_regex,
    'no-storage-status=s'           => \$no_storage_status,
    
    # System mode options
    'warning-policy-last-install=s'  => \$warning_policy_last_install,
    'critical-policy-last-install=s' => \$critical_policy_last_install,
    'warning-conntrack-prct=s'       => \$warning_conntrack_prct,
    'critical-conntrack-prct=s'      => \$critical_conntrack_prct,
    
    # Cluster mode options
    'warning-cluster-node-state=s'   => \$warning_cluster_node_state,
    'critical-cluster-node-state=s'  => \$critical_cluster_node_state,
    'warning-cluster-node-role=s'    => \$warning_cluster_node_role,
    'critical-cluster-node-role=s'   => \$critical_cluster_node_role,
    'warning-cluster-node-status=s'  => \$warning_cluster_node_status,
    'critical-cluster-node-status=s' => \$critical_cluster_node_status,
    'no-link-partner-node=s'         => \$no_link_partner_node,
    
    # Firewall mode options
    'firewall-not-running=s' => \$firewall_not_running_status,
    
    # IPS mode options
    'ips-not-running=s' => \$ips_not_running_status,
) or pod2usage(2);

# Handle special options
if ($version) {
    print "check_sc_continent_snmp.pl v$VERSION\n";
    exit OK;
}

if ($help) {
    pod2usage(1);
}

# Validate required parameters
unless ($host && $mode) {
    print "UNKNOWN: Missing required parameters (host and mode)\n";
    pod2usage(1);
    exit UNKNOWN;
}

# Mode-specific validation
if ($mode eq 'sensors') {
    unless (defined $warning_cpu && defined $critical_cpu && 
            defined $warning_hdd && defined $critical_hdd) {
        print "UNKNOWN: Missing temperature thresholds for sensors mode\n";
        pod2usage(1);
        exit UNKNOWN;
    }
} 
elsif ($mode eq 'cpu') {
    unless (defined $warning_cpu_avg_1m && defined $critical_cpu_avg_1m) {
        print "UNKNOWN: Missing CPU average thresholds for cpu mode\n";
        pod2usage(1);
        exit UNKNOWN;
    }
    
    # Core thresholds are only required if alert-cores is enabled
    if ($alert_cores && !(defined $warning_cpu_core_1m || defined $critical_cpu_core_1m)) {
        print "UNKNOWN: Alert-cores enabled but no core thresholds specified\n";
        pod2usage(1);
        exit UNKNOWN;
    }
    
    if ($alert_cores && !$show_cores) {
        print "UNKNOWN: Alert-cores requires show-cores to be enabled\n";
        pod2usage(1);
        exit UNKNOWN;
    }
}
elsif ($mode eq 'memory') {
    # No threshold validation - all thresholds are optional
}
elsif ($mode eq 'swap') {
    # Validate no-swap-status option
    unless ($no_swap_status =~ /^(ok|warning|critical)$/i) {
        print "UNKNOWN: Invalid no-swap-status value '$no_swap_status'. Must be one of: ok, warning, critical\n";
        exit UNKNOWN;
    }
    $no_swap_status = lc($no_swap_status);
}
elsif ($mode eq 'storage') {
    # Validate no-storage-status option
    unless ($no_storage_status =~ /^(ok|warning|critical)$/i) {
        print "UNKNOWN: Invalid no-storage-status value '$no_storage_status'. Must be one of: ok, warning, critical\n";
        exit UNKNOWN;
    }
    $no_storage_status = lc($no_storage_status);
}
elsif ($mode eq 'system') {
    # No strict validation - thresholds are optional
}
elsif ($mode eq 'cluster') {
    # Validate no-link-partner-node option
    unless ($no_link_partner_node =~ /^(ok|warning|critical)$/i) {
        print "UNKNOWN: Invalid no-link-partner-node value '$no_link_partner_node'. Must be one of: ok, warning, critical\n";
        exit UNKNOWN;
    }
    $no_link_partner_node = lc($no_link_partner_node);
}
elsif ($mode eq 'firewall') {
    # Validate firewall-not-running option
    unless ($firewall_not_running_status =~ /^(ok|warning|critical)$/i) {
        print "UNKNOWN: Invalid firewall-not-running value '$firewall_not_running_status'. Must be one of: ok, warning, critical\n";
        exit UNKNOWN;
    }
    $firewall_not_running_status = lc($firewall_not_running_status);
}
elsif ($mode eq 'ips') {
    # Validate ips-not-running option
    unless ($ips_not_running_status =~ /^(ok|warning|critical)$/i) {
        print "UNKNOWN: Invalid ips-not-running value '$ips_not_running_status'. Must be one of: ok, warning, critical\n";
        exit UNKNOWN;
    }
    $ips_not_running_status = lc($ips_not_running_status);
}
else {
    print "UNKNOWN: Unsupported mode '$mode'\n";
    exit UNKNOWN;
}

# Perform mode-specific checks
if ($mode eq 'sensors') {
    check_sensors();
}
elsif ($mode eq 'cpu') {
    check_cpu();
}
elsif ($mode eq 'memory') {
    check_memory();
}
elsif ($mode eq 'swap') {
    check_swap();
}
elsif ($mode eq 'storage') {
    check_storage();
}
elsif ($mode eq 'system') {
    check_system();
}
elsif ($mode eq 'cluster') {
    check_cluster();
}
elsif ($mode eq 'firewall') {
    check_firewall();
}
elsif ($mode eq 'ips') {
    check_ips();
}

exit OK;

# ========== SUBROUTINES ==========
sub snmp_get {
    my ($oid) = @_;
    my $cmd;
    
    if ($snmp_version eq '3') {
        $cmd = join(' ',
            $SNMPGET,
            '-v3',
            '-l', 'authPriv',
            '-u', shell_quote($snmp_username),
            '-a', $snmp_auth_protocol,
            '-A', shell_quote($snmp_auth_password),
            '-x', $snmp_priv_protocol,
            '-X', shell_quote($snmp_priv_password),
            '-t', $timeout,
            '-Ovq',
            '-Oe',
            shell_quote($host),
            shell_quote($oid)
        );
    } else {
        $cmd = join(' ',
            $SNMPGET,
            '-v', $snmp_version,
            '-c', shell_quote($community),
            '-t', $timeout,
            '-Ovq',
            '-Oe',
            shell_quote($host),
            shell_quote($oid)
        );
    }
    
    my $output = `$cmd 2>&1`;
    my $exit_code = $? >> 8;
    
    if ($exit_code != 0) {
        return (undef, "SNMP command failed (exit $exit_code): $output");
    }
    
    chomp($output);
    return ($output, undef);
}

sub snmp_walk {
    my ($oid) = @_;
    my $cmd;
    
    if ($snmp_version eq '3') {
        $cmd = join(' ',
            $SNMPWALK,
            '-v3',
            '-l', 'authPriv',
            '-u', shell_quote($snmp_username),
            '-a', $snmp_auth_protocol,
            '-A', shell_quote($snmp_auth_password),
            '-x', $snmp_priv_protocol,
            '-X', shell_quote($snmp_priv_password),
            '-t', $timeout,
            '-OQ',
            '-Oe',
            shell_quote($host),
            shell_quote($oid)
        );
    } else {
        $cmd = join(' ',
            $SNMPWALK,
            '-v', $snmp_version,
            '-c', shell_quote($community),
            '-t', $timeout,
            '-OQ',
            '-Oe',
            shell_quote($host),
            shell_quote($oid)
        );
    }
    
    my $output = `$cmd 2>&1`;
    my $exit_code = $? >> 8;
    
    if ($exit_code != 0) {
        return (undef, "SNMP walk failed (exit $exit_code): $output");
    }
    
    return ($output, undef);
}

sub shell_quote {
    my ($arg) = @_;
    return "'" . $arg . "'" if $arg =~ /[^a-zA-Z0-9_\-]/;
    return $arg;
}

sub parse_threshold {
    my ($threshold) = @_;
    return (undef, undef) unless defined $threshold;
    
    # Simple value: 50
    if ($threshold =~ /^(\d+)$/) {
        return (undef, $1);
    }
    
    # Range: 40:50
    if ($threshold =~ /^(\d+):(\d+)$/) {
        return ($1, $2);
    }
    
    # Lower bound only: 40:
    if ($threshold =~ /^(\d+):$/) {
        return ($1, undef);
    }
    
    # Upper bound only: :50
    if ($threshold =~ /^:(\d+)$/) {
        return (undef, $1);
    }
    
    return (undef, undef);
}

sub check_threshold {
    my ($value, $warn_low, $warn_high, $crit_low, $crit_high) = @_;
    
    # Check critical thresholds first
    if (defined $crit_low && defined $value && $value < $crit_low) {
        return CRITICAL;
    }
    if (defined $crit_high && defined $value && $value > $crit_high) {
        return CRITICAL;
    }
    
    # Then check warning thresholds
    if (defined $warn_low && defined $value && $value < $warn_low) {
        return WARNING;
    }
    if (defined $warn_high && defined $value && $value > $warn_high) {
        return WARNING;
    }
    
    return OK;
}

sub check_in_list {
    my ($value, $list_str) = @_;
    return 0 unless defined $list_str;
    
    # Remove quotes if present
    $list_str =~ s/^\"|\"$//g;
    
    my @values = split(/;/, $list_str);
    foreach my $v (@values) {
        $v =~ s/^\s+|\s+$//g; # Trim whitespace
        return 1 if lc($v) eq lc($value);
    }
    return 0;
}

sub get_status_label {
    my ($status_code) = @_;
    return $STATUS_BY_CODE{$status_code} || 'UNKNOWN';
}

sub bytes_to_hr {
    my ($bytes) = @_;
    return "0B" if $bytes == 0;
    
    my @units = ('B', 'KiB', 'MiB', 'GiB', 'TiB');
    my $unit_index = 0;
    my $value = $bytes;
    
    while ($value >= 1024 && $unit_index < scalar(@units)-1) {
        $value /= 1024;
        $unit_index++;
    }
    
    return sprintf("%.2f%s", $value, $units[$unit_index]) if $value < 10;
    return sprintf("%.1f%s", $value, $units[$unit_index]) if $value < 100;
    return sprintf("%.0f%s", $value, $units[$unit_index]);
}

sub format_seconds {
    my ($seconds) = @_;
    return "0 minutes" if $seconds == 0;
    
    my $minutes = int($seconds / 60);
    $seconds %= 60;
    my $hours = int($minutes / 60);
    $minutes %= 60;
    my $days = int($hours / 24);
    $hours %= 24;
    my $months = int($days / 30); # Approximate
    $days %= 30;

    my @parts;
    push @parts, "$months months" if $months > 0;
    push @parts, "$days days" if $days > 0;
    push @parts, "$hours hours" if $hours > 0;
    push @parts, "$minutes minutes" if $minutes > 0;

    return join(', ', @parts);
}

sub check_sensors {
    # Get CPU temperature
    my ($cpu_temp, $error) = snmp_get($OIDS{tempCPU});
    if (defined $error) {
        print "UNKNOWN: $error\n";
        exit UNKNOWN;
    }
    
    # Extract integer value from output
    unless ($cpu_temp =~ /(\d+)/) {
        print "UNKNOWN: Invalid CPU temperature value: '$cpu_temp'\n";
        exit UNKNOWN;
    }
    $cpu_temp = $1 / 100;
    
    # Get HDD temperature
    my ($hdd_temp, $error2) = snmp_get($OIDS{tempHDD});
    if (defined $error2) {
        print "UNKNOWN: $error2\n";
        exit UNKNOWN;
    }
    
    unless ($hdd_temp =~ /(\d+)/) {
        print "UNKNOWN: Invalid HDD temperature value: '$hdd_temp'\n";
        exit UNKNOWN;
    }
    $hdd_temp = $1 / 100;
    
    # Parse threshold ranges
    my ($warn_cpu_low, $warn_cpu_high) = parse_threshold($warning_cpu);
    my ($crit_cpu_low, $crit_cpu_high) = parse_threshold($critical_cpu);
    my ($warn_hdd_low, $warn_hdd_high) = parse_threshold($warning_hdd);
    my ($crit_hdd_low, $crit_hdd_high) = parse_threshold($critical_hdd);
    
    # Validate thresholds
    unless ((defined $warn_cpu_low || defined $warn_cpu_high) &&
            (defined $crit_cpu_low || defined $crit_cpu_high)) {
        print "UNKNOWN: Invalid CPU threshold format '$warning_cpu/$critical_cpu'\n";
        exit UNKNOWN;
    }
    
    unless ((defined $warn_hdd_low || defined $warn_hdd_high) &&
            (defined $crit_hdd_low || defined $crit_hdd_high)) {
        print "UNKNOWN: Invalid HDD threshold format '$warning_hdd/$critical_hdd'\n";
        exit UNKNOWN;
    }
    
    # Check thresholds
    my $exit_code = OK;
    my @verbose_messages;
    my $critical_count = 0;
    my $warning_count = 0;
    my $ok_count = 0;
    
    # CPU temperature check
    my $cpu_status = check_threshold(
        $cpu_temp, 
        $warn_cpu_low, $warn_cpu_high,
        $crit_cpu_low, $crit_cpu_high
    );
    
    my $cpu_status_label = get_status_label($cpu_status);
    my $cpu_verbose_line = "\\_ [$cpu_status_label] Temperature sensor 'CPU' is ${cpu_temp}C";
    push @verbose_messages, $cpu_verbose_line;
    
    if ($cpu_status == CRITICAL) {
        $critical_count++;
        $exit_code = CRITICAL;
    } elsif ($cpu_status == WARNING) {
        $warning_count++;
        $exit_code = WARNING if $exit_code < WARNING;
    } else {
        $ok_count++;
    }
    
    # HDD temperature check
    my $hdd_status = check_threshold(
        $hdd_temp, 
        $warn_hdd_low, $warn_hdd_high,
        $crit_hdd_low, $crit_hdd_high
    );
    
    my $hdd_status_label = get_status_label($hdd_status);
    my $hdd_verbose_line = "\\_ [$hdd_status_label] Temperature sensor 'HDD' is ${hdd_temp}C";
    push @verbose_messages, $hdd_verbose_line;
    
    if ($hdd_status == CRITICAL) {
        $critical_count++;
        $exit_code = CRITICAL if $exit_code < CRITICAL;
    } elsif ($hdd_status == WARNING) {
        $warning_count++;
        $exit_code = WARNING if $exit_code < WARNING;
    } else {
        $ok_count++;
    }
    
    # Prepare output
    my $status_label = get_status_label($exit_code);
    my $perfdata = "'cpu.temperature.celsius'=$cpu_temp;$warning_cpu;$critical_cpu " .
                   "'hdd.temperature.celsius'=$hdd_temp;$warning_hdd;$critical_hdd";
    
    if ($verbose) {
        # Verbose output format - improved summary
        my $summary;
        
        if ($exit_code == OK) {
            $summary = "[OK] All 2 components are ok [2/2 temperatures].";
        } elsif ($exit_code == CRITICAL) {
            $summary = "[CRITICAL] ";
            $summary .= "$critical_count component" . ($critical_count > 1 ? "s" : "") . " in critical state";
            $summary .= ", $warning_count in warning state" if $warning_count > 0;
            $summary .= ".";
        } elsif ($exit_code == WARNING) {
            $summary = "[WARNING] $warning_count component" . ($warning_count > 1 ? "s" : "") . " in warning state.";
        } else {
            $summary = "[UNKNOWN] Unknown state.";
        }
        
        print "$summary\n";
        print join("\n", @verbose_messages) . "\n";
        print " | $perfdata\n";
    } else {
        # Standard output format
        my $output;
        if ($exit_code == OK) {
            $output = "OK: All 2 components are ok [2/2 temperatures].";
        } else {
            # For non-verbose, keep detailed messages
            my @messages;
            push @messages, "CRITICAL: Temperature sensor 'CPU' is ${cpu_temp}C" if $cpu_status == CRITICAL;
            push @messages, "WARNING: Temperature sensor 'CPU' is ${cpu_temp}C" if $cpu_status == WARNING;
            push @messages, "CRITICAL: Temperature sensor 'HDD' is ${hdd_temp}C" if $hdd_status == CRITICAL;
            push @messages, "WARNING: Temperature sensor 'HDD' is ${hdd_temp}C" if $hdd_status == WARNING;
            $output = join('; ', @messages);
        }
        $output .= " | $perfdata";
        print "$output\n";
    }
    
    exit $exit_code;
}

sub check_cpu {
    # Get average CPU load
    my ($avg_load, $error) = snmp_get($OIDS{cpuLoadAvg1Min});
    if (defined $error) {
        print "UNKNOWN: $error\n";
        exit UNKNOWN;
    }
    
    # Extract integer value from output
    unless ($avg_load =~ /(\d+)/) {
        print "UNKNOWN: Invalid CPU load value: '$avg_load'\n";
        exit UNKNOWN;
    }
    $avg_load = $1 / 100;
    
    # Parse thresholds for average load
    my ($warn_avg_low, $warn_avg_high) = parse_threshold($warning_cpu_avg_1m);
    my ($crit_avg_low, $crit_avg_high) = parse_threshold($critical_cpu_avg_1m);
    
    # Validate average thresholds
    unless ((defined $warn_avg_low || defined $warn_avg_high) &&
            (defined $crit_avg_low || defined $crit_avg_high)) {
        print "UNKNOWN: Invalid CPU average threshold format '$warning_cpu_avg_1m/$critical_cpu_avg_1m'\n";
        exit UNKNOWN;
    }
    
    # Prepare variables
    my @core_loads;
    my $core_count = 0;
    my $exit_code = OK;
    my @verbose_messages;
    my $perfdata = "";
    
    # Process core loads if requested
    if ($show_cores) {
        # Get core indexes
        my ($core_indexes, $error_idx) = snmp_walk($OIDS{coreIndex});
        if (defined $error_idx) {
            print "UNKNOWN: $error_idx\n";
            exit UNKNOWN;
        }
        
        # Process each core
        my @indexes = split(/\n/, $core_indexes);
        $core_count = scalar @indexes;
        
        foreach my $line (@indexes) {
            next unless $line =~ /\.(\d+)\s+=\s+(\d+)/;
            my $index = $1;
            my $core_num = $2;
            
            # Get core load
            my $oid = "$OIDS{coreLoadAvg1Min}.$index";
            my ($core_load, $error_core) = snmp_get($oid);
            if (defined $error_core) {
                print "UNKNOWN: $error_core\n";
                exit UNKNOWN;
            }
            
            # Extract integer value from output
            unless ($core_load =~ /(\d+)/) {
                print "UNKNOWN: Invalid core $core_num load value: '$core_load'\n";
                exit UNKNOWN;
            }
            $core_load = $1 / 100;
            
            # Check thresholds if at least one is defined
            my $core_status = OK;
            my $status_label = 'OK';
            
            if (defined $warning_cpu_core_1m || defined $critical_cpu_core_1m) {
                # Parse thresholds for cores
                my ($warn_core_low, $warn_core_high) = parse_threshold($warning_cpu_core_1m);
                my ($crit_core_low, $crit_core_high) = parse_threshold($critical_cpu_core_1m);
                
                $core_status = check_threshold(
                    $core_load, 
                    $warn_core_low, $warn_core_high,
                    $crit_core_low, $crit_core_high
                );
                
                $status_label = get_status_label($core_status);
                
                # Update status if alert-cores enabled
                if ($alert_cores) {
                    if ($core_status > $exit_code) {
                        $exit_code = $core_status;
                    }
                }
            }
            
            push @core_loads, {
                core_num  => $core_num,
                load      => $core_load,
                status    => $core_status,
                status_label => $status_label
            };
            
            # Add to perfdata with max=100
            if (defined $warning_cpu_core_1m || defined $critical_cpu_core_1m) {
                # Handle partially defined thresholds
                my $warn_str = defined $warning_cpu_core_1m ? $warning_cpu_core_1m : '';
                my $crit_str = defined $critical_cpu_core_1m ? $critical_cpu_core_1m : '';
                $perfdata .= "'$core_num#core.cpu.utilization.1m.percentage'=$core_load;$warn_str;$crit_str;0;100 ";
            } else {
                $perfdata .= "'$core_num#core.cpu.utilization.1m.percentage'=$core_load;;;0;100 ";
            }
        }
    }
    
    # Check average load thresholds
    my $avg_status = check_threshold(
        $avg_load, 
        $warn_avg_low, $warn_avg_high,
        $crit_avg_low, $crit_avg_high
    );
    
    # Update overall status
    $exit_code = $avg_status if $avg_status > $exit_code;
    
    # Prepare summary text
    my $summary_text;
    if ($show_cores) {
        $summary_text = sprintf("%d CPU cores average load: %.2f%%", 
                               $core_count, $avg_load);
    } else {
        $summary_text = sprintf("CPU average load: %.2f%%", $avg_load);
    }
    
    # Prepare core details
    if ($show_cores) {
        foreach my $core (@core_loads) {
            push @verbose_messages, sprintf("\\_ [%s] Core %s: %.2f%%", 
                $core->{status_label}, $core->{core_num}, $core->{load});
        }
    }
    
    # Prepare perfdata with max=100 for average
    $perfdata = "'avg.cpu.utilization.1m.percentage'=$avg_load;$warning_cpu_avg_1m;$critical_cpu_avg_1m;0;100 " . $perfdata;
    
    # Get overall status label
    my $overall_label = get_status_label($exit_code);
    
    if ($verbose) {
        # Verbose output format
        print "[$overall_label] $summary_text\n";
        print join("\n", @verbose_messages) . "\n" if @verbose_messages;
        print " | $perfdata\n";
    } else {
        # Standard output format (Nagios compatible)
        my $output = "$overall_label: $summary_text | $perfdata";
        print "$output\n";
    }
    
    exit $exit_code;
}

sub check_memory {
    # Get memory values
    my ($total_bytes, $error1) = snmp_get($OIDS{ramTotalBytes});
    my ($used_bytes, $error2) = snmp_get($OIDS{ramUsedBytes});
    my ($used_percent, $error3) = snmp_get($OIDS{ramUsedPercents});
    
    if (defined $error1) {
        print "UNKNOWN: $error1\n";
        exit UNKNOWN;
    }
    if (defined $error2) {
        print "UNKNOWN: $error2\n";
        exit UNKNOWN;
    }
    if (defined $error3) {
        print "UNKNOWN: $error3\n";
        exit UNKNOWN;
    }
    
    # Extract integer values
    unless ($total_bytes =~ /(\d+)/) {
        print "UNKNOWN: Invalid total memory value: '$total_bytes'\n";
        exit UNKNOWN;
    }
    $total_bytes = $1;
    
    unless ($used_bytes =~ /(\d+)/) {
        print "UNKNOWN: Invalid used memory value: '$used_bytes'\n";
        exit UNKNOWN;
    }
    $used_bytes = $1;
    
    unless ($used_percent =~ /(\d+)/) {
        print "UNKNOWN: Invalid used memory percentage: '$used_percent'\n";
        exit UNKNOWN;
    }
    $used_percent = $1;
    
    # Format bytes to human-readable
    my $total_hr = bytes_to_hr($total_bytes);
    my $used_hr = bytes_to_hr($used_bytes);
    
    # Parse threshold ranges if defined
    my ($warn_prct_low, $warn_prct_high, $crit_prct_low, $crit_prct_high);
    my ($warn_bytes_low, $warn_bytes_high, $crit_bytes_low, $crit_bytes_high);
    
    if (defined $warning_memory_usage_prct) {
        ($warn_prct_low, $warn_prct_high) = parse_threshold($warning_memory_usage_prct);
    }
    
    if (defined $critical_memory_usage_prct) {
        ($crit_prct_low, $crit_prct_high) = parse_threshold($critical_memory_usage_prct);
    }
    
    if (defined $warning_memory_usage_bytes) {
        ($warn_bytes_low, $warn_bytes_high) = parse_threshold($warning_memory_usage_bytes);
    }
    
    if (defined $critical_memory_usage_bytes) {
        ($crit_bytes_low, $crit_bytes_high) = parse_threshold($critical_memory_usage_bytes);
    }
    
    # Initialize status to OK
    my $exit_code = OK;
    
    # Check percentage thresholds
    my $prct_status = OK;
    if (defined $warning_memory_usage_prct || defined $critical_memory_usage_prct) {
        $prct_status = check_threshold(
            $used_percent, 
            $warn_prct_low, $warn_prct_high,
            $crit_prct_low, $crit_prct_high
        );
    }
    
    # Check bytes thresholds
    my $bytes_status = OK;
    if (defined $warning_memory_usage_bytes || defined $critical_memory_usage_bytes) {
        $bytes_status = check_threshold(
            $used_bytes, 
            $warn_bytes_low, $warn_bytes_high,
            $crit_bytes_low, $crit_bytes_high
        );
    }
    
    # Determine overall status (worst of two)
    $exit_code = $prct_status if $prct_status > $exit_code;
    $exit_code = $bytes_status if $bytes_status > $exit_code;
    
    my $status_label = get_status_label($exit_code);
    
    # Prepare perfdata
    my $prct_warn_str = defined $warning_memory_usage_prct ? $warning_memory_usage_prct : '';
    my $prct_crit_str = defined $critical_memory_usage_prct ? $critical_memory_usage_prct : '';
    my $bytes_warn_str = defined $warning_memory_usage_bytes ? $warning_memory_usage_bytes : '';
    my $bytes_crit_str = defined $critical_memory_usage_bytes ? $critical_memory_usage_bytes : '';
    
    my $perfdata = sprintf(
        "'memory.usage.bytes'=%d;%s;%s;0;%d " .
        "'memory.usage.percentage'=%.2f;%s;%s;0;100",
        $used_bytes, $bytes_warn_str, $bytes_crit_str, $total_bytes,
        $used_percent, $prct_warn_str, $prct_crit_str
    );
    
    # Prepare output
    my $message = sprintf("Used Memory: %s (%.2f%%), Total: %s", 
                         $used_hr, $used_percent, $total_hr);
    
    if ($verbose) {
        # Single line output for verbose mode
        print "[$status_label] $message | $perfdata\n";
    } else {
        print "$status_label: $message | $perfdata\n";
    }
    
    exit $exit_code;
}

sub check_swap {
    # Get swap values
    my ($total_bytes, $error1) = snmp_get($OIDS{swapTotalBytes});
    my ($used_bytes, $error2) = snmp_get($OIDS{swapUsedBytes});
    my ($used_percent, $error3) = snmp_get($OIDS{swapUsedPercents});
    
    if (defined $error1) {
        print "UNKNOWN: $error1\n";
        exit UNKNOWN;
    }
    if (defined $error2) {
        print "UNKNOWN: $error2\n";
        exit UNKNOWN;
    }
    if (defined $error3) {
        print "UNKNOWN: $error3\n";
        exit UNKNOWN;
    }
    
    # Extract integer values
    unless ($total_bytes =~ /(\d+)/) {
        print "UNKNOWN: Invalid total swap value: '$total_bytes'\n";
        exit UNKNOWN;
    }
    $total_bytes = $1;
    
    unless ($used_bytes =~ /(\d+)/) {
        print "UNKNOWN: Invalid used swap value: '$used_bytes'\n";
        exit UNKNOWN;
    }
    $used_bytes = $1;
    
    unless ($used_percent =~ /(\d+)/) {
        print "UNKNOWN: Invalid used swap percentage: '$used_percent'\n";
        exit UNKNOWN;
    }
    $used_percent = $1;
    
    # Format bytes to human-readable
    my $total_hr = bytes_to_hr($total_bytes);
    my $used_hr = bytes_to_hr($used_bytes);
    
    # Parse threshold ranges if defined
    my ($warn_low, $warn_high, $crit_low, $crit_high);
    
    if (defined $warning_swap_usage_prct) {
        ($warn_low, $warn_high) = parse_threshold($warning_swap_usage_prct);
    }
    
    if (defined $critical_swap_usage_prct) {
        ($crit_low, $crit_high) = parse_threshold($critical_swap_usage_prct);
    }
    
    # Check if swap is active
    my $exit_code = OK;
    my $message;
    
    if ($total_bytes == 0) {
        # No swap configured
        $exit_code = OK if $no_swap_status eq 'ok';
        $exit_code = WARNING if $no_swap_status eq 'warning';
        $exit_code = CRITICAL if $no_swap_status eq 'critical';
        
        $message = "No active swap";
    } else {
        # Swap is active
        if (defined $warning_swap_usage_prct || defined $critical_swap_usage_prct) {
            $exit_code = check_threshold(
                $used_percent, 
                $warn_low, $warn_high,
                $crit_low, $crit_high
            );
        }
        
        $message = sprintf("Used Swap: %s (%.2f%%), Total: %s", 
                          $used_hr, $used_percent, $total_hr);
    }
    
    my $status_label = get_status_label($exit_code);
    
    # Prepare perfdata
    my $warn_str = defined $warning_swap_usage_prct ? $warning_swap_usage_prct : '';
    my $crit_str = defined $critical_swap_usage_prct ? $critical_swap_usage_prct : '';
    
    my $perfdata = sprintf(
        "'swap.usage.bytes'=%d;;;0;%d " .
        "'swap.usage.percentage'=%.2f;%s;%s;0;100",
        $used_bytes, $total_bytes,
        $used_percent, $warn_str, $crit_str
    );
    
    if ($verbose) {
        # Single line output for verbose mode
        print "[$status_label] $message | $perfdata\n";
    } else {
        print "$status_label: $message | $perfdata\n";
    }
    
    exit $exit_code;
}

sub check_storage {
    # Get storage indexes
    my ($indexes, $error_idx) = snmp_walk($OIDS{fsIndex});
    if (defined $error_idx) {
        print "UNKNOWN: $error_idx\n";
        exit UNKNOWN;
    }
    
    # Process each storage
    my @indexes = split(/\n/, $indexes);
    my @storages;
    my $exit_code = OK;
    my @verbose_messages;
    my $perfdata = "";
    my $critical_count = 0;
    my $warning_count = 0;
    my $ok_count = 0;
    
    foreach my $line (@indexes) {
        next unless $line =~ /\.(\d+)\s+=\s+(\d+)/;
        my $index = $1;
        my $fs_index = $2;
        
        # Get mount point
        my $mount_oid = "$OIDS{fsMountPoint}.$index";
        my ($mount_point, $error_mount) = snmp_get($mount_oid);
        if (defined $error_mount) {
            print "UNKNOWN: $error_mount\n";
            exit UNKNOWN;
        }
        
        # Remove quotes if present
        $mount_point =~ s/^\"|\"$//g;
        
        # Apply filter if specified
        if (defined $filter_storage_regex) {
            unless ($mount_point =~ /$filter_storage_regex/) {
                next;
            }
        }
        
        # Get used bytes
        my $used_bytes_oid = "$OIDS{fsUsedBytes}.$index";
        my ($used_bytes, $error_used) = snmp_get($used_bytes_oid);
        if (defined $error_used) {
            print "UNKNOWN: $error_used\n";
            exit UNKNOWN;
        }
        $used_bytes =~ /(\d+)/;
        $used_bytes = $1;
        
        # Get used percentage (hundredths of percent)
        my $used_percent_oid = "$OIDS{fsUsedPercents}.$index";
        my ($used_percent, $error_percent) = snmp_get($used_percent_oid);
        if (defined $error_percent) {
            print "UNKNOWN: $error_percent\n";
            exit UNKNOWN;
        }
        $used_percent =~ /(\d+)/;
        $used_percent = $1 / 100;  # Convert to actual percentage
        
        # Get free bytes
        my $free_bytes_oid = "$OIDS{fsFreeBytes}.$index";
        my ($free_bytes, $error_free) = snmp_get($free_bytes_oid);
        if (defined $error_free) {
            print "UNKNOWN: $error_free\n";
            exit UNKNOWN;
        }
        $free_bytes =~ /(\d+)/;
        $free_bytes = $1;
        
        # Calculate total bytes
        my $total_bytes = $used_bytes + $free_bytes;
        
        # Format bytes to human-readable
        my $used_hr = bytes_to_hr($used_bytes);
        my $total_hr = bytes_to_hr($total_bytes);
        
        # Parse thresholds
        my ($warn_prct_low, $warn_prct_high) = parse_threshold($warning_storage_usage_prct);
        my ($crit_prct_low, $crit_prct_high) = parse_threshold($critical_storage_usage_prct);
        my ($warn_bytes_low, $warn_bytes_high) = parse_threshold($warning_storage_usage_bytes);
        my ($crit_bytes_low, $crit_bytes_high) = parse_threshold($critical_storage_usage_bytes);
        
        # Check thresholds
        my $prct_status = OK;
        my $bytes_status = OK;
        
        if (defined $warning_storage_usage_prct || defined $critical_storage_usage_prct) {
            $prct_status = check_threshold(
                $used_percent, 
                $warn_prct_low, $warn_prct_high,
                $crit_prct_low, $crit_prct_high
            );
        }
        
        if (defined $warning_storage_usage_bytes || defined $critical_storage_usage_bytes) {
            $bytes_status = check_threshold(
                $used_bytes, 
                $warn_bytes_low, $warn_bytes_high,
                $crit_bytes_low, $crit_bytes_high
            );
        }
        
        # Determine overall status for this storage (worst of two)
        my $storage_status = $prct_status > $bytes_status ? $prct_status : $bytes_status;
        
        # Update global status
        if ($storage_status > $exit_code) {
            $exit_code = $storage_status;
        }
        
        # Count statuses
        if ($storage_status == CRITICAL) {
            $critical_count++;
        } elsif ($storage_status == WARNING) {
            $warning_count++;
        } else {
            $ok_count++;
        }
        
        my $status_label = get_status_label($storage_status);
        
        # Store storage info
        push @storages, {
            mount_point => $mount_point,
            used_bytes  => $used_bytes,
            used_percent => $used_percent,
            total_bytes => $total_bytes,
            status      => $storage_status,
            status_label => $status_label,
            used_hr     => $used_hr,
            total_hr    => $total_hr
        };
        
        # Prepare perfdata
        my $prct_warn_str = defined $warning_storage_usage_prct ? $warning_storage_usage_prct : '';
        my $prct_crit_str = defined $critical_storage_usage_prct ? $critical_storage_usage_prct : '';
        my $bytes_warn_str = defined $warning_storage_usage_bytes ? $warning_storage_usage_bytes : '';
        my $bytes_crit_str = defined $critical_storage_usage_bytes ? $critical_storage_usage_bytes : '';
        
        $perfdata .= sprintf(
            "'%s#storage.usage.bytes'=%d;%s;%s;0;%d " .
            "'%s#storage.usage.percentage'=%.2f;%s;%s;0;100 ",
            $mount_point, $used_bytes, $bytes_warn_str, $bytes_crit_str, $total_bytes,
            $mount_point, $used_percent, $prct_warn_str, $prct_crit_str
        );
    }
    
    # Handle case when no storages found
    unless (@storages) {
        $exit_code = OK if $no_storage_status eq 'ok';
        $exit_code = WARNING if $no_storage_status eq 'warning';
        $exit_code = CRITICAL if $no_storage_status eq 'critical';
        
        my $status_label = get_status_label($exit_code);
        my $message = "No storages found";
        
        if ($verbose) {
            print "[$status_label] $message |\n";
        } else {
            print "$status_label: $message |\n";
        }
        exit $exit_code;
    }
    
    # Prepare verbose output
    foreach my $storage (@storages) {
        push @verbose_messages, sprintf(
            "\\_ [%s] Storage '%s' used: %s (%.2f%%), Total: %s",
            $storage->{status_label},
            $storage->{mount_point},
            $storage->{used_hr},
            $storage->{used_percent},
            $storage->{total_hr}
        );
    }
    
    # Prepare summary
    my $status_label = get_status_label($exit_code);
    my $storage_count = scalar @storages;
    my $summary;
    
    if ($exit_code == OK) {
        $summary = sprintf("[OK] %d Storage%s are ok", $storage_count, $storage_count > 1 ? 's' : '');
    } elsif ($exit_code == CRITICAL) {
        $summary = sprintf("[CRITICAL] %d Storage%s in critical state", $critical_count, $critical_count > 1 ? 's' : '');
        $summary .= sprintf(", %d in warning state", $warning_count) if $warning_count;
    } elsif ($exit_code == WARNING) {
        $summary = sprintf("[WARNING] %d Storage%s in warning state", $warning_count, $warning_count > 1 ? 's' : '');
    } else {
        $summary = "[UNKNOWN] Unknown storage state";
    }
    
    # Output results
    if ($verbose) {
        print "$summary\n";
        print join("\n", @verbose_messages) . "\n";
        print " | $perfdata\n";
    } else {
        if ($exit_code == OK) {
            print "OK: $storage_count storage(s) are ok | $perfdata\n";
        } else {
            # For non-OK, show the worst storage in the main message
            my @critical_storages = grep { $_->{status} == CRITICAL } @storages;
            my @warning_storages = grep { $_->{status} == WARNING } @storages;
            
            my @messages;
            foreach my $storage (@critical_storages) {
                push @messages, sprintf("CRITICAL: Storage '%s' used: %.2f%%", 
                    $storage->{mount_point}, $storage->{used_percent});
            }
            foreach my $storage (@warning_storages) {
                push @messages, sprintf("WARNING: Storage '%s' used: %.2f%%", 
                    $storage->{mount_point}, $storage->{used_percent});
            }
            
            my $output = join('; ', @messages);
            $output .= " | $perfdata";
            print "$output\n";
        }
    }
    
    exit $exit_code;
}

sub check_system {
    my %system_data;
    my $exit_code = OK;
    my @verbose_messages;
    my $perfdata = "";
    my $critical_count = 0;
    my $warning_count = 0;
    my $ok_count = 0;
    
    # Get all system OIDs
    foreach my $key (keys %OIDS) {
        next unless $key =~ /^(continentVersion|nodeUpTime|IPSVersion|KasperskyFeedsVersion|
                             KasperskyHashVersion|UserHashVersion|GeoIPVersion|SkyDNSVersion|
                             lastPolicyInstall|maxConntrack|countConntrack)$/x;
        
        my ($value, $error) = snmp_get($OIDS{$key});
        if (defined $error) {
            print "UNKNOWN: $error\n";
            exit UNKNOWN;
        }
        
        # Remove quotes if present
        $value =~ s/^\"|\"$//g;
        
        $system_data{$key} = $value;
    }
    
    # Check policy last install time
    my $policy_status = OK;
    my $policy_status_label = 'OK';
    if (defined $warning_policy_last_install || defined $critical_policy_last_install) {
        my ($warn_low, $warn_high) = parse_threshold($warning_policy_last_install);
        my ($crit_low, $crit_high) = parse_threshold($critical_policy_last_install);
        
        $policy_status = check_threshold(
            $system_data{lastPolicyInstall}, 
            undef, $warn_high,
            undef, $crit_high
        );
        
        $policy_status_label = get_status_label($policy_status);
        
        if ($policy_status > $exit_code) {
            $exit_code = $policy_status;
        }
        
        # Count status
        if ($policy_status == CRITICAL) {
            $critical_count++;
        } elsif ($policy_status == WARNING) {
            $warning_count++;
        } else {
            $ok_count++;
        }
    } else {
        $ok_count++; # Policy check is not enabled, count as OK
    }
    
    # Format policy time
    my $policy_time = format_seconds($system_data{lastPolicyInstall});
    
    # Check conntrack usage
    my $conntrack_status = OK;
    my $conntrack_status_label = 'OK';
    my $conntrack_percent = 0;
    my $conntrack_percent_str = '0.00%';
    my $conntrack_warn_threshold;
    my $conntrack_crit_threshold;
    
    if ($system_data{maxConntrack} > 0) {
        $conntrack_percent = ($system_data{countConntrack} / $system_data{maxConntrack}) * 100;
        $conntrack_percent_str = sprintf("%.5f%%", $conntrack_percent);
        
        if (defined $warning_conntrack_prct || defined $critical_conntrack_prct) {
            my ($warn_low, $warn_high) = parse_threshold($warning_conntrack_prct);
            my ($crit_low, $crit_high) = parse_threshold($critical_conntrack_prct);
            
            $conntrack_status = check_threshold(
                $conntrack_percent, 
                undef, $warn_high,
                undef, $crit_high
            );
            
            $conntrack_status_label = get_status_label($conntrack_status);
            
            if ($conntrack_status > $exit_code) {
                $exit_code = $conntrack_status;
            }
            
            # Count status
            if ($conntrack_status == CRITICAL) {
                $critical_count++;
            } elsif ($conntrack_status == WARNING) {
                $warning_count++;
            } else {
                $ok_count++;
            }
            
            # Calculate absolute thresholds for perfdata
            $conntrack_warn_threshold = $system_data{maxConntrack} * ($warn_high / 100) if defined $warn_high;
            $conntrack_crit_threshold = $system_data{maxConntrack} * ($crit_high / 100) if defined $crit_high;
        } else {
            $ok_count++; # Conntrack check is not enabled, count as OK
        }
    }
    
    # Prepare perfdata
    my $policy_warn_str = defined $warning_policy_last_install ? $warning_policy_last_install : '';
    my $policy_crit_str = defined $critical_policy_last_install ? $critical_policy_last_install : '';
    my $conntrack_warn_str = defined $conntrack_warn_threshold ? $conntrack_warn_threshold : '';
    my $conntrack_crit_str = defined $conntrack_crit_threshold ? $conntrack_crit_threshold : '';
    
    $perfdata = sprintf(
        "'policy.install.time.seconds'=%d;%s;%s " .
        "'conntrack.count'=%d;%s;%s;0;%d",
        $system_data{lastPolicyInstall}, $policy_warn_str, $policy_crit_str,
        $system_data{countConntrack}, $conntrack_warn_str, $conntrack_crit_str, $system_data{maxConntrack}
    );
    
    # Format uptime
    my $uptime = format_seconds($system_data{nodeUpTime});
    
    # Prepare output
    if (defined $warning_policy_last_install || defined $critical_policy_last_install) {
        push @verbose_messages, sprintf(
            "\\_ [%s] Policy Last Install Time: %s", 
            $policy_status_label, $policy_time
        );
    }
    
    if ($system_data{maxConntrack} > 0 && (defined $warning_conntrack_prct || defined $critical_conntrack_prct)) {
        push @verbose_messages, sprintf(
            "\\_ [%s] Conntrack count: %d (%.5f%%), Maximum: %d", 
            $conntrack_status_label, 
            $system_data{countConntrack},
            $conntrack_percent,
            $system_data{maxConntrack}
        );
    }
    
    push @verbose_messages, "\\_ [OK] Statistics:";
    push @verbose_messages, "   \\_ [OK] Node uptime: $uptime";
    push @verbose_messages, "   \\_ [OK] Current versions:";
    push @verbose_messages, sprintf("      \\_ [OK] Continent: %s", $system_data{continentVersion});
    push @verbose_messages, sprintf("      \\_ [OK] IPS: %s", $system_data{IPSVersion});
    push @verbose_messages, sprintf("      \\_ [OK] KasperskyFeeds: %s", $system_data{KasperskyFeedsVersion});
    push @verbose_messages, sprintf("      \\_ [OK] KasperskyHash: %s", $system_data{KasperskyHashVersion});
    push @verbose_messages, sprintf("      \\_ [OK] UserHash: %s", $system_data{UserHashVersion});
    push @verbose_messages, sprintf("      \\_ [OK] GeoIP: %s", $system_data{GeoIPVersion});
    push @verbose_messages, sprintf("      \\_ [OK] SkyDNS: %s", $system_data{SkyDNSVersion});
    
    # Prepare summary
    my $status_label = get_status_label($exit_code);
    my $summary;
    my $total_checks = $critical_count + $warning_count + $ok_count;
    
    if ($exit_code == OK) {
        $summary = sprintf("[OK] %d Check%s are ok", $total_checks, $total_checks > 1 ? 's' : '');
    } elsif ($exit_code == CRITICAL) {
        $summary = sprintf("[CRITICAL] %d Check%s in critical state", $critical_count, $critical_count > 1 ? 's' : '');
        $summary .= sprintf(", %d in warning state", $warning_count) if $warning_count;
    } elsif ($exit_code == WARNING) {
        $summary = sprintf("[WARNING] %d Check%s in warning state", $warning_count, $warning_count > 1 ? 's' : '');
    } else {
        $summary = "[UNKNOWN] Unknown system state";
    }
    
    # Output results
    if ($verbose) {
        print "$summary\n";
        print join("\n", @verbose_messages) . "\n";
        print " | $perfdata\n";
    } else {
        if ($exit_code == OK) {
            print "OK: System status normal | $perfdata\n";
        } else {
            my @messages;
            push @messages, "CRITICAL: Policy Last Install Time: $policy_time" if $policy_status == CRITICAL;
            push @messages, "WARNING: Policy Last Install Time: $policy_time" if $policy_status == WARNING;
            push @messages, "CRITICAL: Conntrack usage: $conntrack_percent_str" if $conntrack_status == CRITICAL;
            push @messages, "WARNING: Conntrack usage: $conntrack_percent_str" if $conntrack_status == WARNING;
            
            my $output = join('; ', @messages);
            $output .= " | $perfdata";
            print "$output\n";
        }
    }
    
    exit $exit_code;
}

sub check_cluster {
    my %cluster_data;
    my $exit_code = OK;
    my @verbose_messages;
    my $critical_count = 0;
    my $warning_count = 0;
    my $ok_count = 0;
    my $total_checks = 0;  # Счётчик активных проверок
    
    # Get all cluster OIDs
    foreach my $key (keys %OIDS) {
        next unless $key =~ /^(clusterReservStateOn|clusterReservStateRole|clusterReservLink|clusterReservStatus)$/;
        
        my ($value, $error) = snmp_get($OIDS{$key});
        if (defined $error) {
            print "UNKNOWN: $error\n";
            exit UNKNOWN;
        }
        
        # Remove quotes if present
        $value =~ s/^\"|\"$//g;
        
        $cluster_data{$key} = $value;
    }
    
    # Check node state - only if options are defined
    my $node_state_status = OK;
    my $node_state_status_label = 'OK';
    my $node_state = lc($cluster_data{clusterReservStateOn});
    
    if (defined $warning_cluster_node_state || defined $critical_cluster_node_state) {
        $total_checks++;
        
        if (check_in_list($node_state, $critical_cluster_node_state)) {
            $node_state_status = CRITICAL;
            $critical_count++;
        } elsif (check_in_list($node_state, $warning_cluster_node_state)) {
            $node_state_status = WARNING;
            $warning_count++;
        } else {
            $ok_count++;
        }
        
        $node_state_status_label = get_status_label($node_state_status);
        
        if ($node_state_status > $exit_code) {
            $exit_code = $node_state_status;
        }
        
        push @verbose_messages, sprintf(
            "\\_ [%s] Cluster Node state: %s", 
            $node_state_status_label, $node_state
        );
    }
    
    # Check node role - only if options are defined
    my $node_role_status = OK;
    my $node_role_status_label = 'OK';
    my $node_role = lc($cluster_data{clusterReservStateRole});
    
    if (defined $warning_cluster_node_role || defined $critical_cluster_node_role) {
        $total_checks++;
        
        if (check_in_list($node_role, $critical_cluster_node_role)) {
            $node_role_status = CRITICAL;
            $critical_count++;
        } elsif (check_in_list($node_role, $warning_cluster_node_role)) {
            $node_role_status = WARNING;
            $warning_count++;
        } else {
            $ok_count++;
        }
        
        $node_role_status_label = get_status_label($node_role_status);
        
        if ($node_role_status > $exit_code) {
            $exit_code = $node_role_status;
        }
        
        push @verbose_messages, sprintf(
            "\\_ [%s] Cluster Node role: %s", 
            $node_role_status_label, $node_role
        );
    }
    
    # Link status is always checked
    $total_checks++;
    my $link_status = OK;
    my $link_status_label = 'OK';
    my $link_value = $cluster_data{clusterReservLink};
    my $link_state = ($link_value == 1) ? 'active' : 'not active';
    
    if ($link_value == 0) {
        $link_status = $no_link_partner_node eq 'ok' ? OK : 
                      $no_link_partner_node eq 'warning' ? WARNING : CRITICAL;
        
        if ($link_status == CRITICAL) {
            $critical_count++;
        } elsif ($link_status == WARNING) {
            $warning_count++;
        } else {
            $ok_count++;
        }
    } else {
        $ok_count++;
    }
    
    $link_status_label = get_status_label($link_status);
    
    if ($link_status > $exit_code) {
        $exit_code = $link_status;
    }
    
    push @verbose_messages, sprintf(
        "\\_ [%s] Link to partner: %s", 
        $link_status_label, $link_state
    );
    
    # Check node status - only if options are defined
    my $node_status_status = OK;
    my $node_status_status_label = 'OK';
    my $node_status = lc($cluster_data{clusterReservStatus});
    
    if (defined $warning_cluster_node_status || defined $critical_cluster_node_status) {
        $total_checks++;
        
        if (check_in_list($node_status, $critical_cluster_node_status)) {
            $node_status_status = CRITICAL;
            $critical_count++;
        } elsif (check_in_list($node_status, $warning_cluster_node_status)) {
            $node_status_status = WARNING;
            $warning_count++;
        } else {
            $ok_count++;
        }
        
        $node_status_status_label = get_status_label($node_status_status);
        
        if ($node_status_status > $exit_code) {
            $exit_code = $node_status_status;
        }
        
        push @verbose_messages, sprintf(
            "\\_ [%s] Cluster Node status: %s", 
            $node_status_status_label, $node_status
        );
    }
    
    # Prepare summary
    my $status_label = get_status_label($exit_code);
    my $summary;
    
    if ($total_checks == 0) {
        $exit_code = UNKNOWN;
        $summary = "[UNKNOWN] No checks enabled for cluster mode";
    } elsif ($exit_code == OK) {
        $summary = sprintf("[OK] %d Check%s are ok", $total_checks, $total_checks > 1 ? 's' : '');
    } elsif ($exit_code == CRITICAL) {
        $summary = sprintf("[CRITICAL] %d Check%s in critical state", $critical_count, $critical_count > 1 ? 's' : '');
        $summary .= sprintf(", %d in warning state", $warning_count) if $warning_count;
    } elsif ($exit_code == WARNING) {
        $summary = sprintf("[WARNING] %d Check%s in warning state", $warning_count, $warning_count > 1 ? 's' : '');
    } else {
        $summary = "[UNKNOWN] Unknown cluster state";
    }
    
    # Output results
    if ($verbose) {
        print "$summary\n";
        print join("\n", @verbose_messages) . "\n";
        # Empty perfdata line removed in verbose mode
    } else {
        if ($exit_code == UNKNOWN) {
            print "UNKNOWN: No checks enabled for cluster mode |\n";
        } elsif ($exit_code == OK) {
            print "OK: Cluster status normal |\n";
        } else {
            my @messages;
            push @messages, sprintf("CRITICAL: Cluster Node state: %s", $node_state) 
                if (defined $warning_cluster_node_state || defined $critical_cluster_node_state) && $node_state_status == CRITICAL;
            push @messages, sprintf("WARNING: Cluster Node state: %s", $node_state) 
                if (defined $warning_cluster_node_state || defined $critical_cluster_node_state) && $node_state_status == WARNING;
            
            push @messages, sprintf("CRITICAL: Cluster Node role: %s", $node_role) 
                if (defined $warning_cluster_node_role || defined $critical_cluster_node_role) && $node_role_status == CRITICAL;
            push @messages, sprintf("WARNING: Cluster Node role: %s", $node_role) 
                if (defined $warning_cluster_node_role || defined $critical_cluster_node_role) && $node_role_status == WARNING;
            
            push @messages, sprintf("CRITICAL: Link to partner: %s", $link_state) if $link_status == CRITICAL;
            push @messages, sprintf("WARNING: Link to partner: %s", $link_state) if $link_status == WARNING;
            
            push @messages, sprintf("CRITICAL: Cluster Node status: %s", $node_status) 
                if (defined $warning_cluster_node_status || defined $critical_cluster_node_status) && $node_status_status == CRITICAL;
            push @messages, sprintf("WARNING: Cluster Node status: %s", $node_status) 
                if (defined $warning_cluster_node_status || defined $critical_cluster_node_status) && $node_status_status == WARNING;
            
            my $output = join('; ', @messages);
            $output .= " |";
            print "$output\n";
        }
    }
    
    exit $exit_code;
}

sub check_firewall {
    # Get firewall state
    my ($fw_state, $error) = snmp_get($OIDS{fwState});
    if (defined $error) {
        print "UNKNOWN: $error\n";
        exit UNKNOWN;
    }
    
    # Extract integer value
    unless ($fw_state =~ /(\d+)/) {
        print "UNKNOWN: Invalid firewall state value: '$fw_state'\n";
        exit UNKNOWN;
    }
    $fw_state = $1;
    
    # Determine status
    my $exit_code;
    my $message;
    
    if ($fw_state == 1) {
        $exit_code = OK;
        $message = "Firewall is running";
    } else {
        $exit_code = OK if $firewall_not_running_status eq 'ok';
        $exit_code = WARNING if $firewall_not_running_status eq 'warning';
        $exit_code = CRITICAL if $firewall_not_running_status eq 'critical';
        $message = "Firewall not running";
    }
    
    my $status_label = get_status_label($exit_code);
    
    # Output results
    if ($verbose) {
        print "[$status_label] $message\n";
    } else {
        print "$status_label: $message\n";
    }
    
    exit $exit_code;
}

sub check_ips {
    # Get IPS state
    my ($ips_state, $error) = snmp_get($OIDS{ipsComponentState});
    if (defined $error) {
        print "UNKNOWN: $error\n";
        exit UNKNOWN;
    }
    
    # Extract integer value
    unless ($ips_state =~ /(\d+)/) {
        print "UNKNOWN: Invalid IPS state value: '$ips_state'\n";
        exit UNKNOWN;
    }
    $ips_state = $1;
    
    # Determine status
    my $exit_code;
    my $message;
    
    if ($ips_state == 1) {
        $exit_code = OK;
        $message = "IPS is running";
    } else {
        $exit_code = OK if $ips_not_running_status eq 'ok';
        $exit_code = WARNING if $ips_not_running_status eq 'warning';
        $exit_code = CRITICAL if $ips_not_running_status eq 'critical';
        $message = "IPS not running";
    }
    
    my $status_label = get_status_label($exit_code);
    
    # Output results
    if ($verbose) {
        print "[$status_label] $message\n";
    } else {
        print "$status_label: $message\n";
    }
    
    exit $exit_code;
}

__END__

=head1 NAME

check_sc_continent_snmp.pl - Monitoring plugin for Security Code Continent servers

=head1 SYNOPSIS

  # Sensors mode
  ./check_sc_continent_snmp.pl --mode sensors -H 192.168.1.100 \
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
    --warning-cluster-node-status="attention;ok, not ready" --critical-cluster-node-status="problem;down;unavailable;busy" \
    --no-link-partner-node=warning \
    --verbose
    
  # Firewall state check
  ./check_sc_continent_snmp.pl --mode firewall -H 192.168.1.100 \
    --firewall-not-running=critical
    
  # IPS state check
  ./check_sc_continent_snmp.pl --mode ips -H 192.168.1.100 \
    --ips-not-running=warning

=head1 DESCRIPTION

This plugin monitors various components of Security Code Continent servers
using SNMP. Supports multiple modes:
- 'sensors': Temperature monitoring
- 'cpu': CPU load monitoring
- 'memory': RAM usage monitoring
- 'swap': Swap space monitoring
- 'storage': Storage usage monitoring
- 'system': System status monitoring (versions, uptime, policy, conntrack)
- 'cluster': Cluster status monitoring (node state, role, link, status)
- 'firewall': Firewall state monitoring
- 'ips': IPS (Intrusion Prevention System) state monitoring

This plugin uses the external `snmpget` and `snmpwalk` commands from the net-snmp package.

=head1 OPTIONS

=over 4

=item B<--mode|-m>

Operation mode: 'sensors', 'cpu', 'memory', 'swap', 'storage', 'system', 'cluster', 'firewall', or 'ips'

=item B<--host|-H>

SNMP host address (IP or hostname)

=item B<--community|-C>

SNMP community string (default: public)

=item B<--verbose>

Enable verbose output with detailed information

=item B<--show-cores> (CPU mode only)

Enable monitoring of individual CPU cores (thresholds optional)

=item B<--alert-cores> (CPU mode only, requires --show-cores)

Make core status affect overall alert status. When enabled, any warning or critical 
status on a CPU core will elevate the overall status to at least that level.

=item B<--warning-cpu> (Sensors mode)

Warning threshold for CPU temperature (Celsius)

=item B<--critical-cpu> (Sensors mode)

Critical threshold for CPU temperature (Celsius)

=item B<--warning-hdd> (Sensors mode)

Warning threshold for HDD temperature (Celsius)

=item B<--critical-hdd> (Sensors mode)

Critical threshold for HDD temperature (Celsius)

=item B<--warning-cpu-avg-1m> (CPU mode)

Warning threshold for average CPU load over 1 minute (percentage)

=item B<--critical-cpu-avg-1m> (CPU mode)

Critical threshold for average CPU load over 1 minute (percentage)

=item B<--warning-cpu-core-1m> (CPU mode with --show-cores)

Warning threshold for individual CPU cores over 1 minute (percentage)

=item B<--critical-cpu-core-1m> (CPU mode with --show-cores)

Critical threshold for individual CPU cores over 1 minute (percentage)

=item B<--warning-memory-usage-prct> (Memory mode)

Warning threshold for memory usage (percentage)

=item B<--critical-memory-usage-prct> (Memory mode)

Critical threshold for memory usage (percentage)

=item B<--warning-memory-usage-bytes> (Memory mode)

Warning threshold for memory usage in bytes

=item B<--critical-memory-usage-bytes> (Memory mode)

Critical threshold for memory usage in bytes

=item B<--warning-swap-usage-prct> (Swap mode)

Warning threshold for swap usage (percentage)

=item B<--critical-swap-usage-prct> (Swap mode)

Critical threshold for swap usage (percentage)

=item B<--no-swap-status> (Swap mode)

Status to return when no swap is configured (ok|warning|critical, default: ok)

=item B<--warning-storage-usage-prct> (Storage mode)

Warning threshold for storage usage (percentage)

=item B<--critical-storage-usage-prct> (Storage mode)

Critical threshold for storage usage (percentage)

=item B<--warning-storage-usage-bytes> (Storage mode)

Warning threshold for storage usage in bytes

=item B<--critical-storage-usage-bytes> (Storage mode)

Critical threshold for storage usage in bytes

=item B<--filter-storage-regex> (Storage mode)

Regex filter for storage mount points (e.g. '^(sd|vg)' to select only sd* and vg* devices)

=item B<--no-storage-status> (Storage mode)

Status to return when no storage is found (ok|warning|critical, default: ok)

=item B<--warning-policy-last-install> (System mode)

Warning threshold for last policy install time (seconds)

=item B<--critical-policy-last-install> (System mode)

Critical threshold for last policy install time (seconds)

=item B<--warning-conntrack-prct> (System mode)

Warning threshold for conntrack usage (percentage)

=item B<--critical-conntrack-prct> (System mode)

Critical threshold for conntrack usage (percentage)

=item B<--warning-cluster-node-state> (Cluster mode)

Warning threshold for cluster node state (active|standby|unknown, multiple values separated by semicolon)

=item B<--critical-cluster-node-state> (Cluster mode)

Critical threshold for cluster node state (active|standby|unknown, multiple values separated by semicolon)

=item B<--warning-cluster-node-role> (Cluster mode)

Warning threshold for cluster node role (primary|reserved|unknown, multiple values separated by semicolon)

=item B<--critical-cluster-node-role> (Cluster mode)

Critical threshold for cluster node role (primary|reserved|unknown, multiple values separated by semicolon)

=item B<--warning-cluster-node-status> (Cluster mode)

Warning threshold for cluster node status (ok|attention|ok, not ready|problem|down|unavailable|busy, multiple values separated by semicolon)

=item B<--critical-cluster-node-status> (Cluster mode)

Critical threshold for cluster node status (ok|attention|ok, not ready|problem|down|unavailable|busy, multiple values separated by semicolon)

=item B<--no-link-partner-node> (Cluster mode)

Status to return when no link to partner node (ok|warning|critical, default: critical)

=item B<--firewall-not-running> (Firewall mode)

Status to return when firewall is not running (ok|warning|critical, default: critical)

=item B<--ips-not-running> (IPS mode)

Status to return when IPS is not running (ok|warning|critical, default: warning)

=item B<--snmp-version|-v>

SNMP version (1, 2c, or 3, default: 2c)

=item B<--snmp-port|-p>

SNMP port (default: 161)

=item B<--username|-u>

SNMPv3 username (required for SNMPv3)

=item B<--auth-password|-A>

SNMPv3 authentication password

=item B<--auth-protocol|-a>

SNMPv3 authentication protocol (MD5|SHA, default: SHA)

=item B<--priv-password|-P>

SNMPv3 privacy password

=item B<--priv-protocol|-r>

SNMPv3 privacy protocol (DES|AES, default: AES)

=item B<--timeout|-t>

SNMP timeout in seconds (default: 10)

=item B<--help|-h>

Print this help message

=item B<--version|-V>

Print plugin version

=back

=head1 EXAMPLES

  # Sensors mode with verbose output
  ./check_sc_continent_snmp.pl --mode sensors -H 10.10.1.5 \
    --warning-cpu 65 --critical-cpu 75 \
    --warning-hdd 45 --critical-hdd 50 \
    --verbose

  # CPU average and core load with core alerts
  ./check_sc_continent_snmp.pl --mode cpu -H 10.10.1.5 \
    --warning-cpu-avg-1m 80 --critical-cpu-avg-1m 90 \
    --show-cores \
    --warning-cpu-core-1m 90 --critical-cpu-core-1m 95 \
    --alert-cores \
    --verbose

  # Memory usage check
  ./check_sc_continent_snmp.pl --mode memory -H 10.10.1.5 \
    --warning-memory-usage-prct 80 --critical-memory-usage-prct 90

  # Swap usage check with warning when no swap
  ./check_sc_continent_snmp.pl --mode swap -H 10.10.1.5 \
    --warning-swap-usage-prct 50 --critical-swap-usage-prct 70 \
    --no-swap-status warning

  # Storage usage check
  ./check_sc_continent_snmp.pl --mode storage -H 10.10.1.5 \
    --warning-storage-usage-prct 80 --critical-storage-usage-prct 90 \
    --filter-storage-regex='^(sd|vg)' \
    --verbose

  # System status check
  ./check_sc_continent_snmp.pl --mode system -H 10.10.1.5 \
    --warning-policy-last-install=86400 --critical-policy-last-install=172800 \
    --warning-conntrack-prct=80 --critical-conntrack-prct=90 \
    --verbose

  # Cluster status check
  ./check_sc_continent_snmp.pl --mode cluster -H 10.10.1.5 \
    --warning-cluster-node-state="standby" --critical-cluster-node-state="unknown" \
    --warning-cluster-node-role="reserved" --critical-cluster-node-role="unknown" \
    --warning-cluster-node-status="attention;ok, not ready" --critical-cluster-node-status="problem;down;unavailable;busy" \
    --no-link-partner-node=warning \
    --verbose

  # Firewall state check
  ./check_sc_continent_snmp.pl --mode firewall -H 10.10.1.5 \
    --firewall-not-running=critical

  # IPS state check
  ./check_sc_continent_snmp.pl --mode ips -H 10.10.1.5 \
    --ips-not-running=warning

=cut
