package IptConf::NetworkLib;

use strict;
use warnings;
use Exporter qw(import);
use Carp qw(cluck);

# Information about all modules can be found at CPAN (http://www.cpan.org).
use NetAddr::IP qw(:lower);
use NetAddr::IP::Util qw(packzeros);
use Net::DNS;

# selfmade packages
use IptConf::DebugLib qw(d v i e);



################################################################################
#
# Date: 2014-06-10
# Author:
# - Daniel Tiebler
# - Kilian Krause
#
################################################################################
#
# This is a collection of functtions, that are needed to handle network things
# like IP addresses or DNS names.
#
################################################################################
#
# 2014-06-10, Daniel Tiebler
# * The package does not die anymore, if an error occurs. The functions return
#   an undefined value und print an error message to STDERR.
# * Corrected comment of convert_to_cidr_ipv6().
# * Added test in convert_to_cidr_ipv4() and convert_to_cidr_ipv6(), to check,
#   if the given arguments are recognized as IP addresses. Was a FIXME.
#
# 2014-06-06, Daniel Tiebler
# * Changed package declaration to "IptConf::NetworkLib".
# * Corrected packages names of use declaration.
# * Corrected some messages for the output.
#
# 2014-05-07, Daniel Tiebler
# * Removed module Data::Validate::IP, implemented function is_ipv4_address()
#   completely new and function is_ipv6_address() bases on NetAddr::IP now.
# * Added FIXMEs.
#
# 2014-04-30, Daniel Tiebler
# * Added more functionality and named arguments to convert_to_cidr_ipv4() and
#   convert_to_cidr_ipv6().
#
# 2014-04-29, Daniel Tiebler
# * Added convert_to_cidr_ipv4() and convert_to_cidr_ipv6().
# * Added support for CIDR format to is_ipv4_address() and is_ipv6_address().
#
# 2014-04-17, Daniel Tiebler
# * Finished the package.
#
# 2014-04-15, Daniel Tiebler
# * Created package and started to implement some subroutines.
#
################################################################################



# see perlmod manpage
BEGIN {
    # set the version for version checking
    our $VERSION = 0.03;
    # Functions and variables which are exported by default
    our @EXPORT = qw();
    # Functions and variables which can be optionally exported
    our @EXPORT_OK = qw(
        is_ipv4_address
        is_ipv6_address
        resolve_fqdn
        resolve_fqdn_ipv4_address
        resolve_fqdn_ipv6_address
        convert_to_cidr_ipv4
        convert_to_cidr_ipv6
    );
}



# Checks whether the argument looks like an IPv4 address. Accepts leading zeros
# and CIDR notation.
#
# Parameter: string, containing an IPv4 address
# Return value: True, if it looks like an IPv4 address, and false, if it does
#   not. Returns undef, if something went wrong and prints a warning.
sub is_ipv4_address {
    if (! defined($_[0]) || $_[0] eq '') {
        cluck('is_ipv4_address(): First parameter has to be an IPv4 address.');
        return undef();
    }
    my $addr = $_[0];
    my $index = index($addr, '/'); # CIDR?
    if ($index > -1) {
        return 0 if ($index == (length($addr) - 1));
        my $a = substr($addr, $index + 1); # get subnet
        return 0 if ($a < 0 || $a > 32);
        $addr = substr($addr, 0, $index); # remove subnet
    }
    my @tokens;
    @tokens = ($addr =~ m/^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/);
    return 0 if (scalar(@tokens) == 0);
    foreach (@tokens) {
        return 0 if ($_ < 0 || $_ > 255);
    }
    return 1;
}



# Checks whether the argument looks like an IPv6 address.
#
# Parameter: string, containing an IPv6 address
# Return value: True, if it looks like an IPv6 address, and false, if it does
#   not. Returns undef, if something went wrong and prints a warning.
sub is_ipv6_address {
    if (! defined($_[0]) || $_[0] eq '') {
        cluck('is_ipv6_address(): First parameter has to be an IPv6 address.');
        return undef();
    }
    my $addr = new NetAddr::IP($_[0]);
    return 0 if (! defined($addr));
    return ($addr->version() == 6);
}



# Resolves an FQDN and returns the retrieved data strings.
#
# FIXME: Give usage example.
#
# Parameter:
#   * string, containing an FQDN, that has to be resolved
#   * at least one string, containing the query type; is optional and if ommited
#     a query with the type 'ANY' will be performed
# Return value: reference to a hash, where the keys are the query types and the
#   values are references to an array containing the retrieved data strings;
#   returns undef, if something went wrong and prints a warning
sub resolve_fqdn {
    if (scalar(@_) < 1) {
        cluck('resolve_fqdn() has to be called with at least specifying '.
            'an FQDN as first argument.');
        return undef();
    }
    my $fqdn = shift(@_);
    my @query_types = @_;
    if (scalar(@query_types) == 0) {
        push(@query_types, 'ANY');
    }
    
    if (! defined($fqdn) || $fqdn eq '') {
        cluck('resolve_fqdn(): First argument must not be empty.');
        return undef();
    }
    for (my $i = 0; $i < scalar(@query_types); $i++) {
        if (! defined($query_types[$i]) || $query_types[$i] eq '') {
            cluck('resolve_fqdn(): '.($i + 1).'. argument for query '.
                'type must not be empty.');
            return undef();
        }
    }

    my %result;
    
    # Define a new resolver.
    # FIXME: Start and stop resolver using functions, so that the same resolver
    # can be used for several calls to this function.
    my $dns = Net::DNS::Resolver->new();
    $dns->defnames(0);
    $dns->retry(2);
    # timeout in seconds
    # $dns->tcp_timeout(30);
    # $dns->udp_timeout(15);
    $dns->persistent_udp(1);
    
    # Perform queries.
    my $query;
    foreach my $type (@query_types) {
        $query = $dns->query($fqdn, $type);
        if (! defined($query)) {
            if ($dns->errorstring() ne 'NXDOMAIN' &&
                $dns->errorstring() ne 'NOERROR') {
                e('DNS query found no answers: '.$dns->errorstring());
            }
            next;
        }
        foreach my $rr ($query->answer()) {
            push(@{$result{$rr->type()}}, $rr->rdatastr());
        }
    }
    return \%result;
}



# Resolves an FQDN and returns all found IPv4 addresses.
#
# Parameter: string, containing an FQDN, that has to be resolved
# Return value: a reference to an array containing all found IPv4 addresses, if
#   no addresses were found, the array is empty; returns undef, if something
#   went wrong and prints a warning
sub resolve_fqdn_ipv4_address {
    if (scalar(@_) != 1) {
        cluck('resolve_fqdn_ipv4_address() has to be called with an FQDN as '.
            'argument.');
        return undef();
    }
    if (! defined($_[0]) || $_[0] eq '') {
        cluck(
            'resolve_fqdn_ipv4_address(): First argument must not be empty.');
        return undef();
    }

    my $result = resolve_fqdn($_[0], 'A');
    if (! defined($result)) {
        cluck('resolve_fqdn_ipv4_address(): Call to resolve_fqdn() was not '.
            'successful.');
        return undef();
    }
    if (exists($result->{'A'}) && defined($result->{'A'})) {
        return $result->{'A'};
    } else {
        return [];
    }
}



# Resolves an FQDN and returns all found IPv6 addresses.
#
# Parameter: string, containing an FQDN, that has to be resolved
# Return value: a reference to an array containing all found IPv4 addresses, if
#   no addresses were found, the array is empty; returns undef, if something
#   went wrong and prints a warning
sub resolve_fqdn_ipv6_address {
    if (scalar(@_) != 1) {
        cluck('resolve_fqdn_ipv6_address() has to be called with an FQDN as '.
            'argument.');
        return undef();
    }
    if (! defined($_[0]) || $_[0] eq '') {
        cluck(
            'resolve_fqdn_ipv6_address(): First argument must not be empty.');
        return undef();
    }

    my $result = resolve_fqdn($_[0], 'AAAA');
    if (! defined($result)) {
        cluck('resolve_fqdn_ipv6_address(): Call to resolve_fqdn() was not '.
            'successful.');
        return undef();
    }
    if (exists($result->{'AAAA'}) && defined($result->{'AAAA'})) {
        return $result->{'AAAA'};
    } else {
        return [];
    }
}



# Converts the given IPv4 addresses to the CIDR format.
#
# If the address is already in CIDR format, it can be verfied, that the address
# is an appropriate subnet address. If this is not the case, an error message is
# printed to STDERR. See parameter 'verify'.
#
# If the subnet address should be used instead of the given address, set the
# parameter 'subnet' to true.
#
# If one of the given strings is not an IPv4 address, an undefined value is
# returned, although some addresses might be valid. (FIXME: Provide more comfort
# by using an additional parameter.)
#
# Example: $cidr = convert_to_cidr_ipv4(ref => \@array, verify => 0);
#
# Parameter:
#   * 'ref'    => reference to an array with IPv4 addresses
#   * 'verify' => true or false (default)
#   * 'subnet' => true or false (default)
# Return value: reference to an array with IPv4 addresses in CIDR format;
#   returns undef, if something went wrong and prints a warning
sub convert_to_cidr_ipv4 {
    # Verify, that an even number of parameters was provided.
    if (scalar(@_) % 2) {
        cluck(
            'convert_to_cidr_ipv4(): Number of parameters is not even. '.
                'Is there a missing argument?');
        return undef();
    }
    # Get parameters and use defaults.
    my %params = (
        'verify' => 0,
        'subnet' => 0,
        @_
    );
    if (! exists($params{'ref'})) {
        cluck('convert_to_cidr_ipv4() has to be called with a reference to '.
            'an array, that contains IPv4 addresses.');
        return undef();
    }
    if (! defined($params{'ref'}) || ref($params{'ref'}) ne 'ARRAY') {
        cluck('convert_to_cidr_ipv4(): The \'ref\' argument has to be a '.
            'reference to an array.');
        return undef();
    }
    my @args = @{$params{'ref'}};
    if (scalar(@args) == 0) {
        cluck('convert_to_cidr_ipv4(): The array to which the reference of '.
            'the first argument points to is empty.');
        return undef();
    }

    # Convert the IPv4 address.
    my @result = ();
    my $addr;
    foreach (@args) {
        $addr = new NetAddr::IP($_);
        if (! defined($addr)) {
            cluck('convert_to_cidr_ipv4(): The argument \''.$_.'\' is not a '.
                'valid IP address.');
            return undef();
        }
        if ($params{'verify'}) {
            if ($addr->cidr() ne $addr->network()->cidr()) {
                e('IP address \''.$addr->cidr().'\' is not a correct subnet '.
                    'address (\''.$addr->network()->cidr().'\').');
            }
        }
        if ($params{'subnet'}) {
            $addr = $addr->network();
        }
        push(@result, $addr->cidr());
    }
    
    return \@result;
}



# Converts the given IPv6 addresses to the CIDR format.
#
# The zeros in the addresses are compressed. If this is not desired, this can
# be disabled by setting the corresponding parameter to false.
#
# If the address is already in CIDR format, it can be verfied, that the address
# is an appropriate subnet address. If this is not the case, an error message is
# printed to STDERR. See parameter 'verify'.
#
# If the subnet address should be used instead of the given address, set the
# parameter 'subnet' to true.
#
# If one of the given strings is not an IPv6 address, an undefined value is
# returned, although some addresses might be valid. (FIXME: Provide more comfort
# by using an additional parameter.)
#
# Example: $cidr = convert_to_cidr_ipv6(ref => \@array, compress => 0,
#   verify => 0);
#
# Parameter:
#   * 'ref'      => reference to an array with IPv6 addresses
#   * 'compress' => true (default) or false
#   * 'verify'   => true or false (default)
#   * 'subnet'   => true or false (default)
# Return value: reference to an array with zero-compressed IPv6 addresses in
#   CIDR format; returns undef, if something went wrong and prints a warning
sub convert_to_cidr_ipv6 {
    # Verify, that an even number of parameters was provided.
    if (scalar(@_) % 2) {
        cluck('convert_to_cidr_ipv6(): Number of parameters is not even. '.
                'Is there a missing argument?');
        return undef();
    }
    # Get parameters and use defaults.
    my %params = (
        'compress' => 1,
        'verify' => 0,
        'subnet' => 0,
        @_
    );
    if (! exists($params{'ref'})) {
        cluck('convert_to_cidr_ipv6() has to be called with a reference to '.
            'an array, that contains IPv6 addresses.');
        return undef();
    }
    if (! defined($params{'ref'}) || ref($params{'ref'}) ne 'ARRAY') {
        cluck('convert_to_cidr_ipv6(): The \'ref\' argument has to be a '.
            'reference to an array.');
        return undef();
    }
    my @args = @{$params{'ref'}};
    if (scalar(@args) == 0) {
        cluck('convert_to_cidr_ipv6(): The array to which the reference of '.
            'the first argument points to is empty.');
        return undef();
    }

    # Convert the IPv6 address.
    my @result = ();
    my $addr;
    my @tokens;
    foreach (@args) {
        $addr = new NetAddr::IP($_);
        if (! defined($addr)) {
            cluck('convert_to_cidr_ipv6(): The argument \''.$_.'\' is not a '.
                'valid IP address.');
            return undef();
        }
        if ($params{'verify'}) {
            if ($addr->cidr() ne $addr->network()->cidr()) {
                e('IP address \''.$addr->cidr().'\' is not a correct subnet '.
                    'address (\''.$addr->network()->cidr().'\').');
            }
        }
        if ($params{'subnet'}) {
            $addr = $addr->network();
        }
        if ($params{'compress'}) {
            @tokens = split('/', $addr->cidr(), 2);
            $addr = packzeros($tokens[0]).'/'.$tokens[1];
        } else {
            $addr = $addr->cidr();
        }
        push(@result, $addr);
    }
    
    return \@result;
}



1;
