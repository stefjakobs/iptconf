package IptConf::IptConf;

use strict;
use warnings;
use Exporter qw(import);
use Carp qw(cluck);

# selfmade packages
use IptConf::DebugLib qw(d v i e);
use IptConf::NetworkLib qw(
    is_ipv4_address
    is_ipv6_address
    resolve_fqdn_ipv4_address
    resolve_fqdn_ipv6_address
);


################################################################################
#
# Date: 2014-07-02
# Author:
# - Daniel Tiebler
#
################################################################################
#
# Expands special syntax of iptconf and returns lines containing iptables and
# ip6tables commands only. If an specified address is neither an IP address nor
# could it be resolved by DNS, than the module dies.
#
# Example:
#   use IptConf::IptConf qw(expand);
#   my @input = <STDIN>;
#   my ($ip4tables, $ip6tables) = expand(\@input);
#   print("IPv4:\n", @$ip4tables);
#   print("IPv6:\n", @$ip6tables);
#
################################################################################
#
# 2014-07-02, Daniel Tiebler
# * Improved output, if a name cannot be resolved.
#
# 2014-06-24, Daniel Tiebler
# * Added new line to each output line.
#
# 2014-06-23, Daniel Tiebler
# * Added in expand() removing of leading and trailing whitespace of all lines.
#
# 2014-06-10, Daniel Tiebler
# * The package does not die anymore, if an error occurs. The functions return
#   an undefined value und print an error message to STDERR.
#
# 2014-06-06, Daniel Tiebler
# * Changed package declaration to "IptConf::IptConf".
# * Corrected packages names of use declaration and in the example.
#
# 2014-05-06, Daniel Tiebler
# * Improved output of the line in error messages.
# * Corrected handling of native 'iptables' and 'ip6tables' lines.
#
# 2014-04-17, Daniel Tiebler
# * End of refactoring.
#
# 2014-04-14, Daniel Tiebler
# * Added export of subroutines with module Exporter.
# * Begin of refactoring.
#
# 2014-04-11, Daniel Tiebler
# * Created package and copied all subroutines for debuging into the package.
#
################################################################################



# see perlmod manpage
BEGIN {
    # set the version for version checking
    our $VERSION = 0.05;
    # Functions and variables which are exported by default
    our @EXPORT = qw();
    # Functions and variables which can be optionally exported
    our @EXPORT_OK = qw(expand);
}



# Searches for arguments, that specify an IP or a DNS address.
#
# First test for error: "defined($a)".
# Test for IPv4 addresses: "($a & 1)" is true.
# Test for IPv6 addresses: "($a & 2)" is true.
# Test for both addresses: "($a & 3)" is true.
#
# Parameter: command string
# Return value: Returns undef, if an entry was found, that is neither an IP
#   address nor could be resolved to one. Otherwise returns 0 (zero), if no
#   address parameter is found. If an address is found, the first bit (least
#   significant bit) is used for IPv4 addresses and the second bit is used for
#   IPv6 addresses.
sub _contains_address {
    my @line = split(/\s+/, $_[0]);
    my %specifier = (
        '--source' => 0,
        '-s' => 0,
        '--src' => 0,
        '--destination' => 0,
        '-d' => 0,
        '--dst' => 0
    );
    my $result = 0;

    my $token;
    my @addresses;
    my $resolved;
    my $tmp;
    while (scalar(@line)) {
        $token = shift(@line);
        if (exists($specifier{$token})) {
            # get address
            $token = shift(@line);
            # might be a comma separated list
            @addresses = split(',', $token);
            for (@addresses) {
                # Check for IP addresses, their version and resolve DNS names.
                $tmp = is_ipv4_address($_);
                if (! defined($tmp)) {
                    cluck('_contains_address(): Call to is_ipv4_address() was '.
                        'not successful.');
                    return undef();
                }
                if ($tmp) {
                    $result = $result | 1;
                    next;
                }
                
                $tmp = is_ipv6_address($_);
                if (! defined($tmp)) {
                    cluck('_contains_address(): Call to is_ipv6_address() was '.
                        'not successful.');
                    return undef();
                }
                if ($tmp) {
                    $result = $result | 2;
                    next;
                }
                
                # DNS-Lookup
                undef($resolved); # reset

                $tmp = resolve_fqdn_ipv4_address($_);
                if (! defined($tmp)) {
                    cluck('_contains_address(): Call to '.
                        'resolve_fqdn_ipv4_address() was not successful.');
                    return undef();
                }
                if (scalar(@{$tmp})) {
                    $result = $result | 1;
                    $resolved = 1;
                }
                
                $tmp = resolve_fqdn_ipv6_address($_);
                if (! defined($tmp)) {
                    cluck('_contains_address(): Call to '.
                        'resolve_fqdn_ipv6_address() was not successful.');
                    return undef();
                }
                if (scalar(@{$tmp})) {
                    $result = $result | 2;
                    $resolved = 1;
                }
                if (! $resolved) {
                    # If an entry was found, that is neither an IP address
                    # nor could be resolved to one, than this is an error.
                    e('_contains_address(): Could not resolve name: '.
                        '\''.$_.'\'');
                    return undef();
                }
            }
        }
    }
    
    return $result;
}



# data structures for faster and easier processing
my %command_list_ip4 = (
    'iptables'    => 'iptables ', # identity
    'INPUT4'      => 'iptables -A INPUT ',
    'OUTPUT4'     => 'iptables -A OUTPUT ',
    'FORWARD4'    => 'iptables -A FORWARD ',
    'PREROUTING4' => 'iptables -A PREROUTING '
);
my %command_list_ip6 = (
    'ip6tables'   => 'ip6tables ', # identity
    'INPUT6'      => 'ip6tables -A INPUT ',
    'OUTPUT6'     => 'ip6tables -A OUTPUT ',
    'FORWARD6'    => 'ip6tables -A FORWARD ',
    'PREROUTING6' => 'ip6tables -A PREROUTING '
);
my %command_list_ip46 = (
    'INPUT'      => ' -A INPUT ',
    'OUTPUT'     => ' -A OUTPUT ',
    'FORWARD'    => ' -A FORWARD ',
    'PREROUTING' => ' -A PREROUTING ',
    'ip46tables' => ' '
);



# Expands own commands into iptables and ip6tables commands.
#
# Parameter is a reference to an array, that contains lines of commands.
#
# Returns two references to an array containing the commands. The first array
# contains the iptables lines and the second array contains the ip6tables lines.
# Returns undef, if something went wrong and prints a warning.
sub expand {
    if (! wantarray()) {
        cluck('expand() must be called in list context.');
        return undef();
    }
    my $command_lines = shift;
    if (ref($command_lines) ne 'ARRAY') {
        cluck('expand(): argument is not a reference to an array');
        return (undef(), undef());
    }
    my @result_ip4 = ();
    my @result_ip6 = ();
    
    my $line;
    my ($command, $args);
    my $error_occured = 0; # flag, if error occured; allows print all warnings
    for (my $i = 0; $i < scalar(@$command_lines); $i++) {
        $line = @{$command_lines}[$i];
        
        # remove leading and trailing whitspace
        $line =~ s/^\s+//;
        $line =~ s/\s+$//;
        
        # comments and empty lines
        if ($line =~ m/^\s*#/ || $line =~ m/^\s*$/) {
            push(@result_ip4, $line."\n");
            push(@result_ip6, $line."\n");
            next;
        }
        
        ($command, $args) = split(/\s/, $line, 2);

        # command processing
        if (exists($command_list_ip4{$command})) {
            # IPv4
            push(@result_ip4, $command_list_ip4{$command}.$args."\n");
        } elsif (exists($command_list_ip6{$command})) {
            # IPv6
            push(@result_ip6, $command_list_ip6{$command}.$args."\n");
        } elsif (exists($command_list_ip46{$command})) {
            # IPv4 and IPv6
            $line = $command_list_ip46{$command}.$args."\n";
            # If an IP address or a DNS name are specified, it has to be
            # determined, which version of the IP protocol is used.
            my $a = _contains_address($line);
            if (! defined($a)) {
                cluck('expand(): Line contains faulty address.');
                $error_occured = 1;
            } elsif ($a == 0) {
                # no address found
                push(@result_ip4, 'iptables'.$line);
                push(@result_ip6, 'ip6tables'.$line);
            } elsif ($a & 3) {
                # address found
                push(@result_ip4, 'iptables'.$line) if ($a & 1);
                push(@result_ip6, 'ip6tables'.$line) if ($a & 2);
            } else {
                # FIXME: Is this case handled correctly? Discussion necessary.
                cluck('There is a faulty address specification, that could '.
                    'not be resolved, in line: \''.$line.'\'');
                $error_occured = 1;
            }
        } else {
            cluck('Found unknown line: \''.$line.'\'');
            $error_occured = 1;
        }
    }
    
    # Return an undefined value, if an error occured.
    if ($error_occured) {
        return (undef(), undef());
    }
    
    return (\@result_ip4, \@result_ip6);
}



1;
