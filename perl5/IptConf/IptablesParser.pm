package IptConf::IptablesParser;

use warnings;
use strict;
use Text::ParseWords qw(parse_line);
use Exporter qw(import);
use Carp qw(cluck);

# selfmade packages
use IptConf::DebugLib qw(get_debug set_debug set_verbose d v i e);
use IptConf::NetworkLib qw(
    is_ipv4_address
    is_ipv6_address
    resolve_fqdn_ipv4_address
    resolve_fqdn_ipv6_address
    convert_to_cidr_ipv4
    convert_to_cidr_ipv6
);



################################################################################
#
# Date: 2014-08-20
# Author:
# - Daniel Tiebler
# - Kilian Krause
#
################################################################################
#
# This Perl module is very handy to track changes in configuration files for
# firewalls, that use iptables or ip6tables. Providing calls to iptables or
# ip6tables, an output is generated, that is compatible to iptables-save or
# ip6tables-save.
#
# The code is organized as a core and modules. The core is the handling of the
# command lines and the special cases. The modules are used to implement match
# and jump extensions. Note, that some match extensions are also used for
# protocols. This implicates some overhead, but is necessary to help
# implementing new modules easily.
#
# The core is not implemented to the end. This means, some functionality is
# still missing and has to be added as needed. As far as possible the core was
# prepared and documented, so that it should not be too hard to complete it step
# by step. Due to time restrictions some candy for using the data structures was
# omitted.
#
# Since iptables and ip6tables have a large number of extensions, not all
# extensions were implemented. However, if an extension is missing, it can be
# added easily by using a generic parser function and by registering a function,
# that handles the extension. The core does not have to be touched.
#
# Before starting to extend the core, please have a look at the data structures,
# becaues sometimes the functionality is already there, but the missing thing
# has to be registered somewhere.
#
# When specifying parameters for iptables and ip6tables be aware of obeying the
# order for each extension: protocol, match and target. Their parameters have to
# follow directly their specification, because otherwise the parameters will not
# be recognized. However, mixing the paramters themselves and the parameters of
# iptables and ip6tables is allowed.
#
# WARNING: This is not an exhaustive generator for iptables-save or
#   ip6tables-save compatible files. DO NOT use its output with iptables-restore
#   or ip6tables-restore to modify your firewall! On the one hand, it does not
#   check the parameters, although some basic verification is done. On the other
#   hand, it only supports a subset and is far away from beeing complete. That
#   means, neither the functionality of iptables or ip6tables nor all match or
#   target extensions are implemented and therefore not everything is processed
#   properly. Again, do not use it to load the output into the kernel using
#   iptables-restore or ip6tables-restore. Use it for comparing some output of
#   iptables-save or ip6tables-save with modifications of scripts containing
#   calls to iptables or ip6tables, that are normally loaded into the kernel.
#
################################################################################
#
# 2014-08-20, Daniel Tiebler
# * In _apply_rule() corrected handling of inverted list of IP addresses for
#   parameters 'source' and 'destination'.
# * In _apply_rule() corrected handling of IP addresses ending with '/0'.
#
# 2014-06-24, Daniel Tiebler
# * In _get_parameters():
#   - Corrected typo in a comment.
#   - Inserting match extension parameter '- m' after the protocol name, if the
#     parameters following it are recognised by the corresponding match
#     extension. (Was done by the extensions before.)
# * Removed prepending of '- m' in _match_extension_icmp6().
# * Removed prepending of '- m' in _match_extension_tcp().
# * Removed prepending of '- m' in _match_extension_udp().
# * Updated comment of %_match_extensions according to changes listed above.
# * Added sorting of TCP flags in _match_extension_tcp().
# * Added %_match_extension_names_mapping for mapping protocol names to match
#   extension names.
# * Added mapping of protocol names to match extension names in
#   _get_parameters().
# * Removed alias 'ipv6-icmp' in %_match_extensions.
# * Added FIXME in _match_extension_icmp6() for converting type names into type
#   codes.
# * Added FIXME in _match_extension_hashlimit() for a more clever handling of
#   the parameters.
# * Modified _target_extension_log() to use _generic_parameter_parser().
#
# 2014-06-23, Daniel Tiebler
# * Added in _get_parameters() removing of leading and trailing whitespace.
# * Replaced in _get_parameters() confess() with cluck().
# * Corrected definition of parameter count in _match_extension_hashlimit().
# * Corrected comment for _get_ip_addresses().
# * Added in _apply_rule() missing handling of inverse flag ('!') of source and
#   destination addresses.
#
# 2014-06-18, Daniel Tiebler
# * Added comment about specifying the parameters.
# * Corrected parameter name "fragments" to "fragment".
# * Fixed possible use of an unitilized value in _get_parameters().
#
# 2014-06-10, Daniel Tiebler
# * Continued replacing "die" with the return of undefined values.
# * Added a warning to _get_ip_addresses(), if a FQDN resolves to several IP
#   addresses, because this can lead to problems with the comparision, if Round
#   Robin is used.
#
# 2014-06-10, Daniel Tiebler
# * The package does not die anymore, if an error occurs. The functions return
#   an undefined value und print an error message to STDERR.
#
# 2014-06-06, Daniel Tiebler
# * Changed package declaration to "IptConf::IptablesParser".
# * Corrected packages names of use declaration.
#
# 2014-05-12, Daniel Tiebler
# * Corrected flushing and deleting of chains.
# * Added a comment to the constants, that warns about the correct usage.
#
# 2014-05-09, Daniel Tiebler
# * Implemented flushing and deleting of chains.
# * Improved and corrected some comments.
#
# 2014-05-08, Daniel Tiebler
# * Added match extensions 'recent', 'hashlimit'.
# * Added parameter for default parameters to the function
#   _generic_parameter_parser().
# * Added table 'raw' and jump target 'NOTRACK'.
# * Corrected handling of extensions, that do not have any parameters.
# * Added some comments.
#
# 2014-05-07, Daniel Tiebler
# * Added description of this module.
# * Added description, how to add a new extension.
# * Added match extensions 'state', 'udp'.
# * Removed leading whitespace in result of _get_parameters_string() and
#   _target_extension_reject().
# * Added missing replacement of command 'insert' by 'append'.
# * Improved handling of quotation marks in _substitute_quotation_marks().
#
# 2014-05-06, Daniel Tiebler
# * Extracted a generic function out of _match_extension_tcp() to give an easy
#   way to create new match extension functions. An example of the usage of the
#   function _generic_parameter_parser().
# * Corrected handling of the protocol parameter, when no parameter is defined
#   for the given protocol, a match extension ('-m [...]') must not be inserted.
# * Implemented _match_extension_icmp6() as a special case, because the name of
#   the protocol has to be mapped.
# * Added hash %_protocol_names_mapping for mapping protocol names.
# * Disabled debug level.
#
# 2014-05-05, Daniel Tiebler
# * Finished first version.
#
# 2014-04-17, Daniel Tiebler
# * Written from scratch based on "iptconfparser".
#
################################################################################



# Enable debugging.
#set_debug(5);



# see perlmod manpage
BEGIN {
    # set the version for version checking
    our $VERSION = 0.06;
    # Functions and variables which are exported by default
    our @EXPORT = qw();
    # Functions and variables which can be optionally exported
    our @EXPORT_OK = qw(
        generate_output
    );
}



# Warning: Sometimes it is important to help Perl with the interpretation of the
#   constants. Therefore the constants should always be used with parentheses,
#   like a call to a function, when they are used to denote a key value of a
#   hash. Otherwise the name of the constant itself is used.
#
# Example: '$rule_set->{TABLE_FILTER()}' returns the value for the key 'filter'.
# Whereas '$rule_set->{TABLE_FILTER}' tries to access the value for the key
# 'TABLE_FILTER', that does not exist.
use constant {
    # known tables
    TABLE_FILTER => 'filter',
    TABLE_NAT => 'nat',
    TABLE_MANGLE => 'mangle',
    TABLE_RAW => 'raw',
    TABLE_SECURITY => 'security',
    # default chains
    CHAIN_INPUT => 'INPUT',
    CHAIN_FORWARD => 'FORWARD',
    CHAIN_OUTPUT => 'OUTPUT',
    CHAIN_PREROUTING => 'PREROUTING',
    CHAIN_POSTROUTING => 'POSTROUTING',
    # jump target
    TARGET_ACCEPT => 'ACCEPT',
    TARGET_DROP => 'DROP',
    TARGET_QUEUE => 'QUEUE',
    TARGET_RETURN => 'RETURN',
    # IP version strings
    VERSION_IP_V4 => 'IPv4',
    VERSION_IP_V6 => 'IPv6',
    # pattern for extracting the name of a parameter
    REGEX_PARAMETER_NAME => '^--?(\w(?:\w|-)*)',
    # Keys for the hash with the rule set.
    KEY_DEFAULT_CHAINS => 'default_chains',
    KEY_DEFAULT_POLICY => 'default_policy',
    KEY_CHAINS => 'chains',
    KEY_RULES => 'rules',
    KEY_VERSION => 'version'
};



# The order in the array determines the order of the tables for the output.
# If several tables are used, all of them should be somehow touched in the
# same order in every configuration file. The order here is the reverse order.
# If the kernel is started, no table is registered. Changes in a table will
# add this table to the kernel structures. iptables-save will generate the
# output in the reverse order. Therefore the order has to be specified.
use constant TABLE_ORDER_FOR_OUTPUT => (
    TABLE_RAW(),
    TABLE_FILTER()
);



# Used to verify, that an argument really exists.
# FIXME: Generate this hash from the following mapping.
my %_arguments = (
    # long name             short name
    'append' => 0,          'A' => 0,
    'delete' => 0,          'D' => 0,
    'check' => 0,           'C' => 0,
    'insert' => 0,          'I' => 0,
    'replace' => 0,         'R' => 0,
    'list' => 0,            'L' => 0,
    'list-rules' => 0,      'S' => 0,
    'flush' => 0,           'F' => 0,
    'zero' => 0,            'Z' => 0,
    'new-chain' => 0,       'N' => 0,
    'delete-chain' => 0,    'X' => 0,
    'rename-chain' => 0,    'E' => 0,
    'policy' => 0,          'P' => 0,
    'source' => 0,          's' => 0,
    'destination' => 0,     'd' => 0,
    'src' => 0,             's' => 0,
    'dst' => 0,             'd' => 0,
    'protocol' => 0,        'p' => 0,
    'in-interface' => 0,    'i' => 0,
    'jump' => 0,            'j' => 0,
    'table' => 0,           't' => 0,
    'match' => 0,           'm' => 0,
    'numeric' => 0,         'n' => 0,
    'out-interface' => 0,   'o' => 0,
    'verbose' => 0,         'v' => 0,
    'exact' => 0,           'x' => 0,
    'fragment' => 0,        'f' => 0,
    'version' => 0,         'V' => 0,
    'help' => 0,            'h' => 0,
    'line-numbers' => 0,    '0' => 0,
    'modprobe' => 0,        'M' => 0,
    'set-counters' => 0,    'c' => 0,
    'goto' => 0,            'g' => 0,
    'ipv4' => 0,            '4' => 0,
    'ipv6' => 0,            '6' => 0
);



# Used to map short names to long names.
my %_arguments_mapping_to_long_names = (
    'A' => 'append',
    'D' => 'delete',
    'C' => 'check',
    'I' => 'insert',
    'R' => 'replace',
    'L' => 'list',
    'S' => 'list-rules',
    'F' => 'flush',
    'Z' => 'zero',
    'N' => 'new-chain',
    'X' => 'delete-chain',
    'E' => 'rename-chain',
    'P' => 'policy',
    's' => 'source',
    'd' => 'destination',
    'src' => 'source',
    'dst' => 'destination',
    'p' => 'protocol',
    'i' => 'in-interface',
    'j' => 'jump',
    't' => 'table',
    'm' => 'match',
    'n' => 'numeric',
    'o' => 'out-interface',
    'v' => 'verbose',
    'x' => 'exact',
    'f' => 'fragment',
    'V' => 'version',
    'h' => 'help',
    '0' => 'line-numbers',
    'M' => 'modprobe',
    'c' => 'set-counters',
    'g' => 'goto',
    '4' => 'ipv4',
    '6' => 'ipv6'
);



# Used to map long names to short names.
my %_arguments_mapping_to_short_names = (
    'append' => 'A',
    'delete' => 'D',
    'check' => 'C',
    'insert' => 'I',
    'replace' => 'R',
    'list' => 'L',
    'list-rules' => 'S',
    'flush' => 'F',
    'zero' => 'Z',
    'new-chain' => 'N',
    'delete-chain' => 'X',
    'rename-chain' => 'E',
    'policy' => 'P',
    'source' => 's',
    'destination' => 'd',
    'protocol' => 'p',
    'in-interface' => 'i',
    'jump' => 'j',
    'table' => 't',
    'match' => 'm',
    'numeric' => 'n',
    'out-interface' => 'o',
    'verbose' => 'v',
    'exact' => 'x',
    'fragment' => 'f',
    'version' => 'V',
    'help' => 'h',
    'line-numbers' => '0',
    'modprobe' => 'M',
    'set-counters' => 'c',
    'goto' => 'g',
    'ipv4' => '4',
    'ipv6' => '6'
);



# Specifies the order of the parameters like iptabels-save uses them.
my @_argument_order = (
    # commands (always comes first)
    'append', 'delete', 'check', 'insert', 'replace', 'flush', 'zero',
    'new-chain', 'delete-chain', 'rename-chain', 'policy',
    # arguments (order was tested)
    'source', 'destination', 'in-interface', 'out-interface', 'protocol',
    'match', 'jump',
    # other options (order not testet)
     'fragment', 'modprobe', 'goto', 'ipv4', 'ipv6'
    # theres parameters are not used here
    # 'table', 'list', 'list-rules', 'numeric', 'verbose', 'exact', 'version',
    # 'help', 'line-numbers', 'set-counters'
);



# Mapping of protocol names.
my %_protocol_names_mapping = (
    'icmpv6' => 'ipv6-icmp'
);



# Mapping of protocol names to match extension names.
my %_match_extension_names_mapping = (
    'ipv6-icmp' => 'icmp6'
);



# closure for IP version
{
    # Stores the current IP version for the processing.
    my $version;

    # Sets the IP version.
    #
    # Parameter: 'IPv4' or 'IPv6, for specifying the IP version
    # Return value: True, if the version was set. Returns undef, if something
    #   went wrong and prints a warning.
    sub _set_ip_version {
        my $ver = shift();
        if (! defined($ver) ||
            ($ver ne VERSION_IP_V4 && $ver ne VERSION_IP_V6)
            ) {
            cluck('_set_ip_version(): Argument does not specify an IP '.
                'version: \''.$ver.'\'.');
            return undef();
        }
        $version = $ver;
        return 1;
    }
    
    # Is the current IP version IPv4?
    #
    # Parameter: none
    # Return value: True, if version is set to IPv4. Otherwise false.
    sub _is_ip_v4 {
        return ($version eq VERSION_IP_V4);
    }

    # Is the current IP version IPv6?
    #
    # Parameter: none
    # Return value: True, if version is set to IPv6. Otherwise false.
    sub _is_ip_v6 {
        return ($version eq VERSION_IP_V6);
    }
}



# Initialises the data structure for the rule set.
#
# Hierarchy of the rule set of iptables.
# First level is the table, the second one consists of the default chains,
# their policy, additional chains and rules. One rule-entry is a reference to a
# hash containing the command line parameters.
#
# To add a rule set, just add it to the data structure. Use the constants
# defined at the top of the programm, please. New tables have to be added to the
# package global array @_argument_order. Otherwise no output will be generated
# for it.
#
# Parameter: 'IPv4' or 'IPv6, for specifying the IP version
# Return value: a reference to the rule set; returns undef, if something went
#   wrong and prints a warning
sub _init_rule_set {
    my $version = shift();
    if (! defined($version) ||
        ($version ne VERSION_IP_V4 && $version ne VERSION_IP_V6)
        ) {
        cluck('_init_rule_set(): Argument does not specify an IP version: \''.
            $version.'\'.');
        return undef();
    }
    if (! defined(_set_ip_version($version))) {
        cluck('_init_rule_set(): Call to _set_ip_version() was not '.
            'successful.');
        return undef();
    }
    
    my $rule_set = {
        TABLE_FILTER() => {
            # The order of the chains is important for the output.
            KEY_DEFAULT_CHAINS() => [ CHAIN_INPUT, CHAIN_FORWARD, CHAIN_OUTPUT ],
            # Only default chains have a policy.
            KEY_DEFAULT_POLICY() => {},
            # The names of user-defined chains are stored here. The order is
            # not important, because they are sorted alphabetically for the
            # output.
            KEY_CHAINS() => [], # user-defined chains
            # Stores the rules for each chain (default and user-defined).
            # An element of the hash is a references to an array, that contains
            # references to the parameters of a call to iptables. Each parameter
            # is a reference to an array, containing several parameters as
            # strings. Like with the match paramter it is possible, that there
            # are several parameters in one call to iptables.
            # Example: "$rule_set->{$table}->{KEY_RULES}->{$chain}->[0]->
            # {$parameter}->[0]" is the first entry of parameter "$parameter" in
            # the first rule of the chain $chain of table "$table".
            KEY_RULES() => {}
        },
        TABLE_RAW() => {
            KEY_DEFAULT_CHAINS() => [ CHAIN_PREROUTING, CHAIN_OUTPUT ],
            KEY_DEFAULT_POLICY() => {},
            KEY_CHAINS() => [],
            KEY_RULES() => {}
        }
    };
    
    # Set the default policy and empty rule sets for the default chains.
    foreach my $table (keys(%{$rule_set})) {
        for (@{$rule_set->{$table}->{KEY_DEFAULT_CHAINS()}}) {
            $rule_set->{$table}->{KEY_DEFAULT_POLICY()}->{$_} = 'ACCEPT';
            $rule_set->{$table}->{KEY_RULES()}->{$_} = [];
        }
    }

    return $rule_set;
}



# Returns the arguments of a parameter.
#
# Parameter: string containing the parameter and its arguments
# Return value: reference to an array containing the arguments; returns undef,
#   if something went wrong and prints a warning
sub _get_arguments {
    if (! defined($_[0]) && $_[0] eq '') {
        cluck('_get_arguments(): First parameter has to be a string with a '.
            'parameter and its arguments.');
        return undef();
    }
    my @arguments = split(' ', $_[0]);
    # Sometimes there is an exclamation mark, so remove it.
    if ($arguments[0] eq '!') {
        shift(@arguments);
    }
    # Remove parameter name.
    shift(@arguments);
    
    return \@arguments;
}



# Substitutes single quotation with double quotation marks.
# iptables-save uses double quotes as quotation marks normally.
#
# FIXME: Should be more sophisticated and used for every input! Try the
#   following: "Hello", "Hello.", 'Hello', 'Hello"', 'Hello\!', 'Hello!',
#   "Hello", 'Hello world!', 'Hello_world!', Hello\.world\!
#
# Parameter: string
# Return value: If the content of the string is enclosed in single quotation
#   marks, they are substituted with double quotation marks and this string is
#   returned. If the comment constists of small letters, capital letters,
#   numbers, hyphens and underscores, the quotation marks are removed. Otherwise
#   the original string is returned.
sub _substitute_quotation_marks {
    my $result = $_[0];
    
    # Verify parameter.
    if (! defined($result) || length($result) < 2) {
        return $result;
    }
    
    # Are surrounding quotation marks present?
    if (index($result, '\'') == 0 &&
        rindex($result, '\'') == (length($result) - 1)) {
        
        # Can the quotation marks be removed?
        if ($result =~ m/^.[a-zA-Z0-9_-]*.$/) {
            # Remove quotation marks.
            $result = substr($result, 1, (length($result) - 2));
        } else {
            # Cannot remove, so substitute.
            substr($result, 0, 1, '"');
            substr($result, (length($result) - 1) , 1, '"');
        }
    }
    
    return $result;
}



# Auxiliary function, that collects parameters for any extension, that fulfills
# the following conditions:
# * Short name parameters start with '-'.
# * Long name parameters start with '--'.
# * The number of arguments of a parameter is fix.
#
# Features:
# * parameter names can be defined
# * default parameters can be defined
# * parameter names can be mapped (for example long names to short names)
# * parameter may have arguments, but the number has to be fix
# * an order for the parameters can be specified, so that the parameters are
#   sorted as needed, and only the ordered parameters are returned
# * the exclamation mark ('!') used for negation or inversion is supported
# * paramater substitution is used to substitute aliases for complex parameters
#   (for example '--syn' to '--tcp-flags FIN,SYN,RST,ACK SYN')
#
# See function _match_extension_tcp() as an example, that uses almost all
# parameters. The function _match_extension_recent() uses defaults and does some
# special handling of the parameter.
#
# Parameters:
# Note: The name of a parameter is always the name including the leading dashes.
# * 'parameter_ref'       => reference to the command line parameters
# * 'i_ref'               => reference to the current position
# * 'param_names'         => reference to a hash, that contains the names of the
#                            parameters to be parsed; the key is the name of a
#                            parameter and the value defines the number of its
#                            arguments
# * 'params_default'      => reference to a hash, that contains default
#   (optional)               parameters and default values; the key is the name
#                            of a parameter and the value is a string containing
#                            the name and possibly arguments of the parameter
#                            like on the command line; default parameters are
#                            overwritten by the found parameters
# * 'params_invert'       => reference to a hash, that contains the names of all
#   (optional)               parameters, that are allowed to be inverted using
#                            the exclamation mark; the key is the name of a
#                            parameter and the value has to be true
# * 'param_names_mapping' => reference to a hash for mapping one parameter name
#   (optional)               to another; the key is the "from" name and the
#                            value is the "to" name
# * 'param_substitution'  => reference to a hash for parameter substitutions;
#   (optional)               the key is the name of the parameter, that has to
#                            be substituted and the value is a reference to an
#                            array, where the first element is the name of the
#                            new parameter and the second element is the
#                            complete parameter line, including necessary
#                            arguments
# * 'params_order'        => reference to an array, where every element is the
#   (optional)               name of a parameter; the parameters are ordered
#                            according to the array; note that parameter names,
#                            that are not in this array, are ignored; so this
#                            can be used as a filter
# Return value: reference to an array, where all found parameters are returned,
#   or a reference to an empty array; the elements are strings containing one
#   parameter with its arguments; returns undef, if something went wrong and
#   prints a warning
sub _generic_parameter_parser {
    # FIXME: Should mandatory parameters be checked?
    
    my $error_occured = 0;
    
    # Verify, that an even number of parameters was provided.
    if (scalar(@_) % 2) {
        cluck('_generic_parameter_parser(): Number of parameters is not even. '.
            'Is there a missing argument?');
            $error_occured = 1;
    }
    # Get parameters and use defaults.
    my %params = ( @_ );
    my $parameters_ref = $params{'parameter_ref'};
    if (! defined($parameters_ref)) {
        cluck('_generic_parameter_parser(): Parameter \'parameter_ref\' is '.
            'not defined!');
        $error_occured = 1;
    }
    my $i_ref = $params{'i_ref'};
    if (! defined($i_ref)) {
        cluck('_generic_parameter_parser(): Parameter \'i_ref\' is not '.
            'defined!');
        $error_occured = 1;
    }
    my $param_names = $params{'param_names'};
    if (! defined($param_names)) {
        cluck('_generic_parameter_parser(): Parameter \'param_names\' is '.
            'not defined!');
        $error_occured = 1;
   }
    my $params_default = $params{'params_default'} // {};
    my $params_invert = $params{'params_invert'} // {};
    my $param_names_mapping = $params{'param_names_mapping'} // {};
    my $param_substitution = $params{'param_substitution'};
    my $params_order = $params{'params_order'};

    if ($error_occured) {
        return undef();
    }
    
    # Parameters found on the command line.
    my %params_found = ();

    # Collect the parameters until the end or until an unknown one is seen.
    my $name;
    my $inverse = 0;
    my $counter;
    my @arguments;
    while (defined($parameters_ref->[${$i_ref}])) {
        if ($parameters_ref->[${$i_ref}] eq '!') {
            $inverse = 1;
            ${$i_ref}++;
            next;
        } elsif (exists($param_names->{$parameters_ref->[${$i_ref}]})) {
            $name = $parameters_ref->[${$i_ref}];
            ${$i_ref}++;
            
            # Use short names.
            if (exists($param_names_mapping->{$name})) {
                $name = $param_names_mapping->{$name};
                # Only one parameter with the same name is allowed.
                if (exists($params_found{$name})) {
                    cluck('Only one parameter allowed: \''.$name.'\'.');
                    return undef();
                }
            }
            
            # Are there any argumens to this parameter?
            $counter = $param_names->{$name};
            @arguments = ();
            while ($counter > 0) {
                if (! defined($parameters_ref->[${$i_ref}])) {
                    cluck('Missing argument in match extension \'tcp\' for '.
                        'parameter \''.$name.'\'.');
                    return undef();
                }
                push(@arguments, _substitute_quotation_marks(
                    $parameters_ref->[${$i_ref}]));
                ${$i_ref}++;
                $counter--;
            }
            
            # Assemble parameter line.
            if (scalar(@arguments) == 0) {
                $params_found{$name} = $name;
            } else {
                $params_found{$name} = $name.' '.join(' ', @arguments);
            }
            
            # Prepend exclamation mark.
            if ($inverse == 1) {
                if (exists($params_invert->{$name})) {
                    $params_found{$name} = '! '.$params_found{$name};
                    $inverse = 0;
                } else {
                    cluck('The parameter \''.$name.'\' must not be preceded '.
                        'by an exclamation mark (\'!\').');
                    return undef();
                }
            }
        } else {
            # We are ready.
            last;
        }
    }
    
    # If an exclamation mark was found but for an unknown parameter, set the
    # pointer correctly.
    if ($inverse) {
        ${$i_ref}--;
    }
    
    # If default parameters are defined, merge them with the found parameters.
    %params_found = ( %{$params_default}, %params_found );

    # Substitute shortcuts.
    if (defined($param_substitution)) {
        my ($k, $v); # key and value
        foreach (keys(%params_found)) {
            $k = $_;
            if (exists($param_substitution->{$k})) {
                $v = $param_substitution->{$k};
                # Does the parameter already exist.
                if (exists($params_found{$v->[0]})) {
                    cluck('Shortcut \''.$k.'\' and parameter \''.$v->[0].
                        '\' are not allowed at the same time.');
                    return undef();
                }
                
                # Does it start with an exclamation mark?
                if (index($params_found{$k}, '!') == 0) {
                    if (exists($params_invert->{$k})) {
                        $v->[1] = '! '.$v->[1];
                        $inverse = 0;
                    } else {
                        cluck('The parameter \''.$k.'\' must not be '.
                            'preceded by an exclamation mark (\'!\').');
                        return undef();
                    }
                }
                
                # Substitute parameter.
                delete($params_found{$k});
                $params_found{$v->[0]} = $v->[1];
            }
        }
    }
    # Bring all parameters in the correct order, additionally filtering them,
    # and generate the result.
    @arguments = ();
    if (defined($params_order)) {
        for (my $i = 0; $i < scalar(@{$params_order}); $i++) {
            if (exists($params_found{$params_order->[$i]})) {
                push(@arguments, $params_found{$params_order->[$i]});
            }
        }
    } else {
        @arguments = values(%params_found);
    }

    return \@arguments;
}



# Collect parameters for match extension 'comment'.
#
# See comment for hash _match_extensions for parameters and return value of the
# subroutine.
sub _match_extension_comment {
    my $parameters_ref = $_[0];
    my $i_ref = $_[1];
    my $result = '';
    
    if (${$i_ref} + 1 < scalar(@{$parameters_ref}) &&
        $parameters_ref->[${$i_ref}] eq '--comment') {
        ${$i_ref}++;
        $result = $parameters_ref->[${$i_ref}];
        # iptables-save uses double quotes as quotation marks, so replace single
        # quotes.
        $result = _substitute_quotation_marks($result);
        $result = '--comment '.$result;
        ${$i_ref}++;
    } else {
        cluck('Missing parameter \'--comment\' in match extension '.
            '\'comment\'.');
        return undef();
    }
    return $result;
}



# Collect parameters for match extension 'tcp'.
#
# See comment for hash _match_extensions for parameters and return value of the
# subroutine.
sub _match_extension_tcp {
    my $parameters_ref = $_[0];
    my $i_ref = $_[1];
    my %param_names = (
        '--source-port'         => 1, '--sport' => 1,
        '--destination-port'    => 1, '--dport' => 1,
        '--tcp-flags'           => 2,
        '--syn'                 => 0,
        '--tcp-option'          => 1
    );
    my %params_invert = (
        '--source-port'         => 0, '--sport' => 0,
        '--destination-port'    => 0, '--dport' => 0,
        '--tcp-flags'           => 0,
        '--syn'                 => 0,
        '--tcp-option'          => 0
    );
    my %param_names_mapping = (
        '--source-port' => '--sport',
        '--destination-port' => '--dport'
    );
    my %param_substitution = (
        '--syn' => ['--tcp-flags', '--tcp-flags FIN,SYN,RST,ACK SYN']
    );
    my @params_order = ('--sport', '--dport', '--tcp-option', '--tcp-flags');
    
    my $parameters = _generic_parameter_parser(
        parameter_ref       => $parameters_ref,
        i_ref               => $i_ref,
        param_names         => \%param_names,
        params_invert       => \%params_invert,
        param_names_mapping => \%param_names_mapping,
        param_substitution  => \%param_substitution,
        params_order        => \@params_order
    );
    if (! defined($parameters)) {
        cluck('_match_extension_tcp(): Call to _generic_parameter_parser() '.
            'was not successful.');
        return undef();
    }
    
    # Correct the order of TCP flags.
    my $invers = 0;
    my (@tokens, @mask, @comp );
    my %flags = ();
    my @flag_order = qw( FIN SYN RST PSH ACK URG ALL NONE );
    foreach (@{$parameters}) {
        if (index($_, '--tcp-flags') == 0 || index($_, '! --tcp-flags') == 0) {
            @tokens = split(' ', $_);
            
            # Is the parameter inverted?
            if ($tokens[0] eq '!') {
                $invers = 1;
                shift(@tokens);
            } else {
                $invers = 0;
            }
            
            # Parameter complete?
            if (scalar(@tokens) != 3) {
                # Save programming time and do nothing, because the error will
                # be recognised later.
                next;
            }
            
            @mask = split(',', $tokens[1]);
            undef(%flags); # reset hash
            # Fill the hash.
            foreach (@mask) {
                $flags{$_} = 0;
            }
            @mask = ();
            # Sort flags.
            foreach (@flag_order) {
                if (exists($flags{$_})) {
                    push(@mask, $_);
                }
            }

            @comp = split(',', $tokens[2]);
            undef(%flags); # reset hash
            # Fill the hash.
            foreach (@comp) {
                $flags{$_} = 0;
            }
            @comp = ();
            # Sort flags.
            foreach (@flag_order) {
                if (exists($flags{$_})) {
                    push(@comp, $_);
                }
            }
            
            # Generate parameter.
            $_ = ($invers?'! ':'').'--tcp-flags '.join(',', @mask).' '.
                join(',', @comp);
        }
    }

    my $result = '';
    if (scalar(@{$parameters} > 0)) {
        $result = join(' ', @{$parameters});
    }

    return $result;
}



# Collect parameters for match extension 'icmp6'.
#
# See comment for hash _match_extensions for parameters and return value of the
# subroutine.
sub _match_extension_icmp6 {
    my $parameters_ref = $_[0];
    my $i_ref = $_[1];
    my %param_names = (
        '--icmpv6-type' => 1
    );
    my %params_invert = (
        '--icmpv6-type' => 0
    );

    my $parameters = _generic_parameter_parser(
        parameter_ref       => $parameters_ref,
        i_ref               => $i_ref,
        param_names         => \%param_names,
        params_invert       => \%params_invert,
    );
    if (! defined($parameters)) {
        cluck('_match_extension_icmp6(): Call to _generic_parameter_parser() '.
            'was not successful.');
        return undef();
    }
    
    # FIXME: Convert type names to type codes.

    my $result = '';
    if (scalar(@{$parameters} > 0)) {
        $result = join(' ', @{$parameters});
    }

    return $result;
}



# Collect parameters for match extension 'state'.
#
# See comment for hash _match_extensions for parameters and return value of the
# subroutine.
sub _match_extension_state {
    my $parameters_ref = $_[0];
    my $i_ref = $_[1];
    my %param_names = (
        '--state' => 1
    );
    my %params_invert = (
        '--state' => 0
    );
    
    my $parameters = _generic_parameter_parser(
        parameter_ref       => $parameters_ref,
        i_ref               => $i_ref,
        param_names         => \%param_names,
        params_invert       => \%params_invert,
    );
    if (! defined($parameters)) {
        cluck('_match_extension_state(): Call to _generic_parameter_parser() '.
            'was not successful.');
        return undef();
    }

    my $result = '';
    if (scalar(@{$parameters} > 0)) {
        $result = join(' ', @{$parameters});
    }

    return $result;
}



# Collect parameters for match extension 'udp'.
#
# See comment for hash _match_extensions for parameters and return value of the
# subroutine.
sub _match_extension_udp {
    my $parameters_ref = $_[0];
    my $i_ref = $_[1];
    my %param_names = (
        '--source-port'         => 1, '--sport' => 1,
        '--destination-port'    => 1, '--dport' => 1,
    );
    my %params_invert = (
        '--source-port'         => 0, '--sport' => 0,
        '--destination-port'    => 0, '--dport' => 0,
    );
    my %param_names_mapping = (
        '--source-port' => '--sport',
        '--destination-port' => '--dport'
    );
    my @params_order = ('--sport', '--dport');
    
    my $parameters = _generic_parameter_parser(
        parameter_ref       => $parameters_ref,
        i_ref               => $i_ref,
        param_names         => \%param_names,
        params_invert       => \%params_invert,
        param_names_mapping => \%param_names_mapping,
        params_order        => \@params_order
    );
    if (! defined($parameters)) {
        cluck('_match_extension_udp(): Call to _generic_parameter_parser() '.
            'was not successful.');
        return undef();
    }

    my $result = '';
    if (scalar(@{$parameters} > 0)) {
        $result = join(' ', @{$parameters});
    }

    return $result;
}



# Collect parameters for match extension 'recent'.
#
# See comment for hash _match_extensions for parameters and return value of the
# subroutine.
sub _match_extension_recent {
    my $parameters_ref = $_[0];
    my $i_ref = $_[1];
    my %param_names = (
        '--name'        => 1,
        '--set'         => 0,
        '--rsource'     => 0,
        '--rdest'       => 0,
        '--rcheck'      => 0,
        '--update'      => 0,
        '--remove'      => 0,
        '--seconds'     => 1,
        '--reap'        => 0,
        '--hitcount'    => 1,
        '--rttl'        => 0
    );
    my %params_default = (
        '--name'    => '--name DEFAULT'
    );
    my %params_invert = (
        '--set'         => 0,
        '--rcheck'      => 0,
        '--update'      => 0,
        '--remove'      => 0
    );
    my @params_order = ('--set', '--rcheck', '--update', '--remove',
        '--seconds', '--reap', '--hitcount', '--rttl', '--name', '--rsource',
        '--rdest' );
    
    my $parameters = _generic_parameter_parser(
        parameter_ref       => $parameters_ref,
        i_ref               => $i_ref,
        param_names         => \%param_names,
        params_default      => \%params_default,
        params_invert       => \%params_invert,
        params_order        => \@params_order
    );
    if (! defined($parameters)) {
        cluck('_match_extension_recent(): Call to _generic_parameter_parser() '.
            'was not successful.');
        return undef();
    }
    
    # Special case handling.
    # If neither '--rsource' nor '--rdest' are set, the default is '--rsource'.
    # If only '--rdest' is set, '--rsource' will not be set as default, because
    # both are exclusive.
    # If both, '--rsource' and '--rdest', are set, the last one on the command
    # line wins.
    my $found_rsource = 0;
    my $index_rsource = -1;
    my $found_rdest = 0;
    my $index_rdest = -1;
    for (my $i = 0; $i < scalar(@{$parameters}); $i++) {
        if ($parameters->[$i] eq '--rsource') {
            $found_rsource = 1;
            $index_rsource = $i;
        } elsif ($parameters->[$i] eq '--rdest') {
            $found_rdest = 1;
            $index_rdest = $i;
        }
    }
    if (! $found_rsource && ! $found_rdest) {
        # None is set, so set the default. This is easy, because it is always
        # the last parameter.
        push(@{$parameters}, '--rsource');
    } elsif ($found_rsource && $found_rdest) {
        # If both are set, the last one wins.
        # Search in the original list for the last entry.
        $found_rsource = 0;
        $found_rdest = 0;
        for (my $i = ${$i_ref} - 1; $parameters_ref->[$i] ne 'recent'; $i--) {
            if ($parameters_ref->[$i] eq '--rsource') {
                $found_rsource = 1;
                last;
            }
            if ($parameters_ref->[$i] eq '--rdest') {
                $found_rdest = 1;
                last;
            }
        }
        # If one is found, the other is removed.
        if ($found_rsource) {
            splice(@{$parameters}, $index_rdest, 1);
        } elsif ($found_rdest) {
            splice(@{$parameters}, $index_rsource, 1);
        } else {
            cluck('This should not happen!!! Have a look at the source '.
                'code.');
            return undef();
        }
    }

    my $result = '';
    if (scalar(@{$parameters} > 0)) {
        $result = join(' ', @{$parameters});
    }

    return $result;
}



# Collect parameters for match extension 'hashlimit'.
#
# See comment for hash _match_extensions for parameters and return value of the
# subroutine.
sub _match_extension_hashlimit {
    my $parameters_ref = $_[0];
    my $i_ref = $_[1];
    my %param_names = (
        '--hashlimit-upto' => 1,
        '--hashlimit-above' => 1,
        '--hashlimit-burst' => 1,
        '--hashlimit-mode' => 1,
        '--hashlimit-srcmask' => 1,
        '--hashlimit-dstmask' => 1,
        '--hashlimit-name' => 1,
        '--hashlimit-htable-size' => 1,
        '--hashlimit-htable-max' => 1,
        '--hashlimit-htable-expire' => 1,
        '--hashlimit-htable-gcinterval' => 1
    );
    my %params_default = (
        '--hashlimit-burst'         => '--hashlimit-burst 5',
        '--hashlimit-htable-expire' => '--hashlimit-htable-expire 1'
    );
    my @params_order = ('--hashlimit-upto', '--hashlimit-above',
        '--hashlimit-burst', '--hashlimit-mode', '--hashlimit-name',
        '--hashlimit-htable-size', '--hashlimit-htable-max',
        '--hashlimit-htable-gcinterval', '--hashlimit-htable-expire',
        '--hashlimit-srcmask', '--hashlimit-dstmask');
    
    my $parameters = _generic_parameter_parser(
        parameter_ref       => $parameters_ref,
        i_ref               => $i_ref,
        param_names         => \%param_names,
        params_default      => \%params_default,
        params_order        => \@params_order
    );
    if (! defined($parameters)) {
        cluck('_match_extension_hashlimit(): Call to '.
            '_generic_parameter_parser() was not successful.');
        return undef();
    }
    
    # FIXME: Substitute long names of entities with short names:
    # * 'minute' => 'min' and
    # * 'second' => 'sec'.
    
    # FIXME: The default parameter '--hashlimit-htable-expire' depends on the
    # used unit and has to be implemented accordingly:
    # * '/sec' => 1
    # * '/min' => 60
    # * '/hour' => 3600
    # * '/day' => 86400
    
    # FIXME: Using seconds as unit the values for hashlimit-above are rounded
    # somehow. This has to be investigated.

    # Special case handling.
    # The extension accepts numbers as argument for '--hashlimit-upto' and
    # '--hashlimit-above', but iptables-save adds the unit. So add it here, too.
    # Note, the parameters are exclusive.
    foreach (@{$parameters}) {
        if (index($_, '--hashlimit-upto') == 0 ||
            index($_, '--hashlimit-above') == 0
            ) {
            if (index($_, '/') == -1) {
                # Append the default unit.
                $_ .= '/sec';
            }
            last;
        }
    }

    my $result = '';
    if (scalar(@{$parameters} > 0)) {
        $result = join(' ', @{$parameters});
    }

    return $result;
}


# match extensions (see manpage of iptables)
#
# How to add a new match extension?
# Write a new function called '_match_extension_<name of extension>', that
# fulfills the interface (parameter and return value) as described below, and
# register it in the hash %_match_extensions. The key of this hash is the name
# of the match extension (the name after '-m' or '--match') and the value is a
# reference to the function for this extension. If a match extension is found,
# the registered function is called to obtain the parameter string.
#
# Note, that match extensions are also used for protocols ('-p' or
# '--protocol').
#
# It also might be necessary to register one function with several names, like
# 'icmp6' and 'ipv6-icmp', because of an alias.
#
# Have a look at _generic_parameter_parser(), which is an auxiliary function.
#
# Parameters:
#   * reference to the whole paremter array
#   * reference to the current index
# Return value: a string containing the parameters of the match extension in
#   sorted order, like iptables-save would order it; the index points to the
#   next token, that has to be processed; returns undef, if something went wrong
#   and prints a warning
#
my %_match_extensions = (
    'comment' => \&_match_extension_comment,
    'hashlimit' => \&_match_extension_hashlimit,
    'icmp6' => \&_match_extension_icmp6,
    'ipv6-icmp' => \&_match_extension_icmp6, # alias for protocol
    'recent' => \&_match_extension_recent,
    'state' => \&_match_extension_state,
    'tcp' => \&_match_extension_tcp,
    'udp' => \&_match_extension_udp
);



# Collect parameters for target extension 'LOG'.
#
# See comment for hash _target_extensions for parameters and return value of the
# subroutine.
sub _target_extension_log {
    my $parameters_ref = $_[0];
    my $i_ref = $_[1];
    my %param_names = (
        '--log-level' => 1,
        '--log-prefix' => 1,
        '--log-tcp-sequence' => 0,
        '--log-tcp-options' => 0,
        '--log-ip-options' => 0,
        '--log-uid' => 0
    );
    my @params_order = ('--log-prefix', '--log-level', '--log-tcp-sequence',
        '--log-tcp-options', '--log-ip-options', '--log-uid');
    
    my $parameters = _generic_parameter_parser(
        parameter_ref       => $parameters_ref,
        i_ref               => $i_ref,
        param_names         => \%param_names,
        params_order        => \@params_order
    );
    if (! defined($parameters)) {
        cluck('_target_extension_log(): Call to _generic_parameter_parser() '.
            'was not successful.');
        return undef();
    }

    my $result = '';
    if (scalar(@{$parameters} > 0)) {
        $result = join(' ', @{$parameters});
    }

    return $result;
}



# Collect parameters for target extension 'REJECT'.
#
# See comment for hash _target_extensions for parameters and return value of the
# subroutine.
sub _target_extension_reject {
    my $parameters_ref = $_[0];
    my $i_ref = $_[1];
    my $result = '';
    
	if (defined($parameters_ref->[${$i_ref}]) &&
        $parameters_ref->[${$i_ref}] eq '--reject-with'
        ) {
        $result = '--reject-with';
        ${$i_ref}++;
        # Get the next parameter.
        if (defined($parameters_ref->[${$i_ref}])) {
            # FIXME: No verification here.
            $result .= ' '.$parameters_ref->[${$i_ref}];
            ${$i_ref}++;
        } else {
            cluck('Missing parameter in target extension \'REJECT\' for '.
                'parameter \'--reject-with\'.');
            return undef();
        }
    } else {
        # Parameter is missing. Add it.
        if (_is_ip_v4()) {
            # IPv4
            $result .= '--reject-with icmp-port-unreachable';
        } else {
            # IPv6
            $result .= '--reject-with icmp6-port-unreachable';
        }
    }
    
    return $result;
}



# Collect parameters for target extension 'NOTRACK'.
#
# See comment for hash _target_extensions for parameters and return value of the
# subroutine.
sub _target_extension_notrack {
    # There are no parameters to this target extension.
    return '';
}


# target extensions (see manpage of iptables)
#
# How to add a new target extension?
# Write a new function called '_target_extension_<name of extension>', that
# fulfills the interface (parameter and return value) as described below, and
# register it in the hash %_target_extensions. The key of this hash is the name
# of the target extension (the name after '-j' or '--jump') and the value is a
# reference to the function for this extension. If a target extension is found,
# the registered function is called to obtain the parameter string.
#
# Have a look at _generic_parameter_parser(), which is an auxiliary function.
#
# Parameters:
#   * reference to the whole paremter array
#   * reference to the current index
# Return value: a string containing the parameters of the target extension in
#   sorted order, like iptables-save would order it; the index points to the
#   next token, that has to be processed; returns undef, if something went wrong
#   and prints a warning
#
my %_target_extensions = (
    'LOG'     => \&_target_extension_log,
    'NOTRACK' => \&_target_extension_notrack,
    'REJECT'  => \&_target_extension_reject
);



# Parses the call to iptables for parameters and returns them.
#
# Parameter: one line containing a call to iptables
# Return value: a reference to a hash containing the parameters, where the long
#   names are used as keys and the value is a reference to an array, that
#   contains strings, whereby each string constists of one parameter with its
#   arguments including a leading '!' sometimes; returns undef, if something
#   went wrong and prints a warning
sub _get_parameters {
    d('_get_parameters()', 2, 'Processing line: '.$_[0]);
    # Remove leading and trailing whitespace.
    $_[0] =~ s/^\s+//; # remove leading whitespace
    $_[0] =~ s/\s+$//; # remove trailing whitespace
    # Split line preserving whitespace within pairs of quotation marks.
    my @parameters = parse_line('\s+', 1, $_[0]);
    d('_get_parameters()', 5, 'Found tokens: >>'.join('<< >>', @parameters).
        '<<');
    if ($parameters[0] ne 'iptables' && $parameters[0] ne 'ip6tables') {
        cluck('_get_parameters(): First word of command line is neither '.
            '\'iptables\' nor \'ip6tables\': \''.$parameters[0].'\'.');
        return undef();
    }

    # Parse for parameters.
    my %result;
    my $regex_pattern = REGEX_PARAMETER_NAME;
    my $inverse = 0; # exclamation mark
    my $name; # name of the current parameter
    my $current; # current parameter and its options
    my $name_tmp; # name of a match extension or jump target
    my $name_tmp_2; # name of a match extension or jump target
    my $params_tmp; # resulting parameter of a function call
    my $j; # auxiliary counter
    for (my $i = 1; $i < scalar(@parameters); $i++) {
        if ($parameters[$i] eq '!') {
            # Found exclamation mark ('!').
            $inverse = 1;
            next;
        } elsif (index($parameters[$i], '-') == 0) {

            # Found a parameter.
            $current = $parameters[$i];
            $current =~ m/$regex_pattern/;
            $name = $1;
            
            # If the parameter is unknown abort!
            if (! exists($_arguments{$name})) {
                cluck('_get_parameters(): Unknown parameter \''.$parameters[$i].
                    '\' found. Remaining line: \''.
                    join(' ', @parameters[$i .. $#parameters]).'\'.');
                return undef();
            }
            
            # If name is a short name, replace it with a long name for internal
            # use. Otherwise replace the parameter on the command line with the
            # short name.
            if (exists($_arguments_mapping_to_long_names{$name})) {
                $name = $_arguments_mapping_to_long_names{$name};
            } else {
                # iptables-save uses short names in its output, so convert long
                # names to short names automatically.
                if (exists($_arguments_mapping_to_short_names{$name})) {
                    $current = '-'.$_arguments_mapping_to_short_names{$name};
                } else {
                    cluck('_get_parameters(): No short name found for the '.
                        'long name \''.$name.'\'');
                    return undef();
                }
            }

            # Does it have an inverse flag?
            if ($inverse) {
                $current = '! '.$current;
                $inverse = 0;
            }

            #d('_get_parameters()', 5, 'Found parameter called \''.$name.'\'.');
            
            if ($name eq 'protocol') {
                # If a protocol is specified, some match extensions can be used.
                # That means, handle their parameter, too.
                # For example 'tcp', 'udp' and 'icmp'.
                
                # First of all, save the current parameter.
                $i++; # Points now to the name of the protocol.
                if (! defined($parameters[$i])) {
                    cluck('_get_parameters(): Missing protocol name after \''.
                        $parameters[$i - 1].'\'.');
                    return undef();
                }
                $name_tmp = $parameters[$i];
                
                # Mapping protocol names.
                if (exists($_protocol_names_mapping{$name_tmp})) {
                    $name_tmp = $_protocol_names_mapping{$name_tmp};
                }
                
                # Mapping protocol name to match extension name.
                if (exists($_match_extension_names_mapping{$name_tmp})) {
                    $name_tmp_2 = $_match_extension_names_mapping{$name_tmp};
                } else {
                    $name_tmp_2 = $name_tmp;
                }
                
                # Add the name to the current line.
                $current .= ' '.$name_tmp;
                
                # If the next parameter is not know to iptables, it might be a
                # parameter of a match extension of the protocol.
                $j = $i + 1; # next parameter
                if (defined($parameters[$j]) && $parameters[$j] eq '!') {
                    d('_get_parameters()', 5, 'Protocol parameter: Found '.
                        '\'!\'.');
                    $j++;
                }
                d('_get_parameters()', 5, 'Protocol parameter is : \''.
                    (defined($parameters[$j])?$parameters[$j]:'').'\'.');

                # Leaving the source code here as a comment, if the regular
                # expression has to be debugged.
                #
                #$parameters[$j] =~ m/$regex_pattern/;
                #d('_get_parameters()', 5, 'Eval: ('.$1.') '.
                #    ((! exists($_arguments{$1}))?'true':'false'));
                
                if (defined($parameters[$j]) &&
                    index($parameters[$j], '-') == 0 &&
                    $parameters[$j] =~ m/$regex_pattern/ &&
                    ! exists($_arguments{$1})
                    ) {
                    d('_get_parameters', 5, 'Protocol parameter: Found '.
                        'parameter, that is unknown to iptables.');
                    if (! exists($_match_extensions{$name_tmp_2})) {
                        # Oops! Is a match extension missing?
                        cluck('_get_parameters(): Parameter after the protcol '.
                            'is unknown to iptables. Either the parameter is '.
                            'missing in the parameter list for iptables or '.
                            'the match extension (\''.$name_tmp_2.'\') is '.
                            'missing for the protocol (\''.$name_tmp.
                            '\'). Remaining line: \''.
                            join(' ', @parameters[($i + 1) .. $#parameters]).
                            '\'.');
                        return undef();
                    }
                    $i++; # Points now one position after the protocol name.
                    # Call the extension.
                    d('_get_parameters()', 2, 'Call to match extension (for '.
                        'protocoll) \''.$name_tmp_2.'\'.');
                    $params_tmp = $_match_extensions{$name_tmp_2}->
                        (\@parameters, \$i);
                    if (! defined($params_tmp)) {
                        cluck('_get_parameters(): Call to match extension \''.
                            $name_tmp_2.'\' was not successful.');
                        return undef();
                    }
                    # It is necessary to prepend '-m <name of extension> ' to
                    # the result, because it is implicitely generated by
                    # iptables-save or ip6tables-save.
                    if (length($params_tmp) > 0) {
                        $current .= ' -m '.$name_tmp_2.' '.$params_tmp;
                    }
                    
                    # Continue after the parameter, that was processed last.
                    # The index has to be corrected, because it will be
                    # incremented automatically by the loop.
                    $i--;
                }
            } elsif ($name eq 'match') {
                # Let the match extension collect its remaining parameters.

                $i++; # Points now to the match extension name.
                if (! defined($parameters[$i])) {
                    cluck('_get_parameters(): Missing match extension after \''.
                        $parameters[$i - 1].'\'.');
                    return undef();
                }
                $name_tmp = $parameters[$i];
                $current .= ' '.$name_tmp;
                
                if (exists($_match_extensions{$name_tmp})) {
                    # Point to the first parameter of the match extension.
                    $i++;
                    # Call the extension.
                    d('_get_parameters()', 2, 'Call to match extension \''.
                        $name_tmp.'\'.');
                    $params_tmp = $_match_extensions{$name_tmp}->
                        (\@parameters, \$i);
                    if (! defined($params_tmp)) {
                        cluck('_get_parameters(): Call to match extension \''.
                            $name_tmp.'\' was not successful.');
                        return undef();
                    }
                    if (length($params_tmp) > 0) {
                        $current .= ' '.$params_tmp;
                    }
                        
                    # Continue after the parameter, that was processed last.
                    # The index has to be corrected, because it will be
                    # incremented automatically by the loop.
                    $i--;
                } else {
                    # No appropriate match extension found.
                    cluck('_get_parameters(): Unknown match extension: \''.
                        $name_tmp.'\'.');
                    return undef();
                }
            } elsif ($name eq 'jump') {
                # Let the target extension collect its remaining parameters.

                $i++; # Points now to the name of the jump target.
                if (! defined($parameters[$i])) {
                    cluck('_get_parameters(): Missing jump target after \''.
                        $parameters[$i - 1].'\'.');
                    return undef();
                }
                $name_tmp = $parameters[$i];
                $current .= ' '.$name_tmp;
                
                if ($name_tmp eq TARGET_ACCEPT || $name_tmp eq TARGET_DROP ||
                    $name_tmp eq TARGET_QUEUE || $name_tmp eq TARGET_RETURN
                    ) {
                    # builtin targets (ACCEPT, DROP, QUEUE and RETURN)
                    
                    # nothing to do
                } elsif (exists($_target_extensions{$name_tmp})) {
                    # target extensions (see manpage)
                    
                    # Point to the first parameter of the target extension.
                    $i++;
                    # Call the extension.
                    d('_get_parameters()', 2, 'Call to target extension \''.
                        $name_tmp.'\'.');
                    $params_tmp = $_target_extensions{$name_tmp}->
                        (\@parameters, \$i);
                    if (! defined($params_tmp)) {
                        cluck('_get_parameters(): Call to target extension \''.
                            $name_tmp.'\' was not successful.');
                        return undef();
                    }
                    if (length($params_tmp) > 0) {
                        $current .= ' '.$params_tmp;
                    }

                    # Continue after the parameter, that was processed last.
                    # The index has to be corrected, because it will be
                    # incremented automatically by the loop.
                    $i--;
                } else {
                    # Might be a user-defined chain. Since this cannot be
                    # checked here, have a look at the following parameter. If
                    # it is known to iptables, the probability is very high,
                    # that it is a user-defined chain. Otherwise it might be a
                    # target extension, that is not implemented yet.
                    $j = $i + 1; # next parameter
                    if (defined($parameters[$j]) && $parameters[$j] eq '!') {
                        $j++;
                    }
                    if (defined($parameters[$j]) &&
                        index($parameters[$j], '-') == 0 &&
                        $parameters[$j] =~ m/$regex_pattern/ &&
                        ! exists($_arguments{$1})
                        ) {
                        cluck('_get_parameters(): The parameter after the '.
                            'jump target is not known to iptables. Either the '.
                            'parameter is missing in the parameter list for '.
                            'iptables or the target extension is missing for '.
                            'the target (\''.$name_tmp.'\'). Remaining line: '.
                            '\''.
                            join(' ', @parameters[($i + 1) .. $#parameters]).
                            '\'.');
                        return undef();
                    }
                    # otherwise, nothing to do
                }
            } else {
                # Collect the remaining parameters as options.

                $i++;
                while ($i < scalar(@parameters)) {
                    if ($parameters[$i] eq '!' ||
                        $parameters[$i] =~ m/$regex_pattern/) {
                        if ($parameters[$i] eq '!' || exists($_arguments{$1})) {
                            last;
                        } else {
                            # FIXME: A better handling of this might be better,
                            #   but it should be sufficient not to know about
                            #   the number of options.
                            cluck('_get_parameters(): Unknown parameter \''.
                                $parameters[$i].'\' found while collecting '.
                                'options. Remaining line: \''.
                                join(' ', @parameters[$i .. $#parameters]).
                                '\'.');
                            return undef();
                        }
                    }
                    # Append option.
                    $current .= ' '.$parameters[$i];
                    $i++;
                }
                # Continue after the parameter, that was processed last.
                # The index has to be corrected, because it will be incremented
                # automatically by the loop.
                $i--;
            }
        } else {
            # Something went wrong, since all parameters should have been
            # consumed.
            cluck('_get_parameters(): Unknown parameter \''.$parameters[$i].
                '\' found. Remaining line: \''.
                join(' ', @parameters[$i .. $#parameters]).
                '\'.');
            return undef();
        }

        # Save the current parameter and its options.
        d('_get_parameters()', 4, 'Adding parameter to the result: \''.$current.
            '\'.');
        if (! exists($result{$name})) {
            $result{$name} = []; # Create reference to empty array.
        }
        # Special handling of the parameter 'protocol', because the protcol
        # and the match extension are handled saparately by iptables-save.
        # The 'protocol' has its location, but the position of the corresponding
        # match extension is as it appears on the command line.
        if (index($current, '-p') == 0 || index($current, '! -p') == 0) {
            $j = index($current, ' -m ');
            if ($j > -1) {
                $j++; # points now to '-' of ' -m '
                # Add the match extension.
                if (! exists($result{'match'})) {
                    $result{'match'} = []; # Create reference to empty array.
                }
                d('_get_parameters()', 5, 'Splitting protocol parameter:');
                push($result{'match'}, substr($current, $j));
                d('_get_parameters()', 5, '* \''.substr($current, $j).'\'');
                $current = substr($current, 0, $j - 1); # '- 1' because of ' '
                d('_get_parameters()', 5, '* \''.$current.'\'');
            }
        }
        # FIXME: Enforce only one entry for some parameters, if a more
        #   sophisticated handling is desired.
        push(@{$result{$name}}, $current);
    }

    return \%result;
}



# Will generate a list of IP addresses resolving Full Qualified Domain Names
# (FQDN), if necessary. The IP adresses, that are resolved, will be sorted in a
# human readable fashion, if a FQDN resolves to several IP addresses (still a
# TODO). The addresses will be returned in CIDR format and zeros in IPv6
# addresses are compressed.
#
# Parameter:
#   * string, containing a comma separated list of IP addresses or FQDNs,
#       like the parameter '--source' and '--destination' of iptables expect it
# Return value: reference to an array of IP addresses; returns undef, if
#   something went wrong and prints a warning
sub _get_ip_addresses {
    if (! defined($_[0]) || $_[0] eq '') {
        cluck('_get_ip_addresses(): First parameter has to be a comma '.
            'separated string of IP addresses or FQDNs: \''.
            (defined($_[0])?$_[0]:'undef').'\'.');
        return undef();
    }

    my $address_string = $_[0];
    my $resolved; # resolved FQDNs
    my $tmp;
    my @result = ();
    for my $addr (split(',', $address_string)) {
        d('_get_ip_addresses()', 5, 'Address: '.$addr);
        # Is it an IP address?
        if (_is_ip_v4()) {
            $tmp = is_ipv4_address($addr);
            if (! defined($tmp)) {
                cluck('_get_ip_addresses(): Call to is_ipv4_address() was not '.
                    'successful.');
                return undef();
            }
            if ($tmp) {
                d('_get_ip_addresses()', 5, 'Is IPv4 address: '.$addr);
                push(@result, $addr);
                next;
            }
            
            $tmp = is_ipv6_address($addr);
            if (! defined($tmp)) {
                cluck('_get_ip_addresses(): Call to is_ipv6_address() was not '.
                    'successful.');
                return undef();
            }
            if ($tmp) {
                cluck('_get_ip_addresses(): Found IPv6 address while '.
                    'processing IPv4: \''.$addr.'\'.');
                return undef();
            }
        } elsif (_is_ip_v6()) {
            $tmp = is_ipv6_address($addr);
            if (! defined($tmp)) {
                cluck('_get_ip_addresses(): Call to is_ipv6_address() was not '.
                    'successful.');
                return undef();
            }
            if ($tmp) {
                d('_get_ip_addresses()', 5, 'Is IPv6 address: '.$addr);
                push(@result, $addr);
                next;
            }
            
            $tmp = is_ipv4_address($addr);
            if (! defined($tmp)) {
                cluck('_get_ip_addresses(): Call to is_ipv4_address() was not '.
                    'successful.');
                return undef();
            }
            if ($tmp) {
                cluck('_get_ip_addresses(): Found IPv4 address while '.
                    'processing IPv6: \''.$addr.'\'.');
                return undef();
            }
        }

        # Not an IP address. Might be a FQDN, so try to resolve it.
        if (_is_ip_v4()) {
            # IPv4
            d('_get_ip_addresses()', 5, 'Resolving IPv4 address: '.$addr);
            $resolved = resolve_fqdn_ipv4_address($addr);
            if (! defined($resolved)) {
                cluck('_get_ip_addresses(): Call to '.
                    'resolve_fqdn_ipv4_address() was not successful.');
                return undef();
            }
        } else {
            # IPv6
            d('_get_ip_addresses()', 5, 'Resolving IPv6 address: '.$addr);
            $resolved = resolve_fqdn_ipv6_address($addr);
            if (! defined($resolved)) {
                cluck('_get_ip_addresses(): Call to '.
                    'resolve_fqdn_ipv6_address() was not successful.');
                return undef();
            }
        }
        if (scalar(@{$resolved}) == 0) {
            cluck('_get_ip_addresses(): Could not resolve FQDN: \''.$addr.'\'');
            return undef();
        }
        
        # Warn, if one FQDN resolves to several IP addresses, because a
        # Round Robin algorithm makes comparison pretty complex.
        if (scalar(@{$resolved}) > 1) {
            warn('_get_ip_addresses(): FQDN \''.$addr.'\' resolved to '.
                'several IP addresses: '.join(', ', @{$resolved}).'. This '.
                'might lead to problems with the comparison, if Round Robin '.
                'is used. How about using a subnet instead?');
        }

        # TODO
        # Human readable sorting should be used. It should be implemented in the
        # NetworkLib: either in the resolve functions or as a separate function.
        # It should consider also the network prefix.
        if (scalar(@{$resolved}) != 0) {
            push(@result, @{$resolved});
            next;
        }
    }

    # Convert into CIDR format.
    if (_is_ip_v4()) {
        # IPv4
        $tmp = convert_to_cidr_ipv4(ref => \@result, verify => 1, subnet => 1);
        if (! defined($tmp)) {
            cluck('_get_ip_addresses(): Call to convert_to_cidr_ipv4() was '.
                'not successful.');
            return undef();
        }
        return $tmp;
    } else {
        # IPv6
        $tmp = convert_to_cidr_ipv6(ref => \@result, verify => 1, subnet => 1);
        if (! defined($tmp)) {
            cluck('_get_ip_addresses(): Call to convert_to_cidr_ipv6() was '.
                'not successful.');
            return undef();
        }
        return $tmp;
    }
}



# All commands should be mutual exclusive.
#
# Parameter: reference to a hash containing the parameters
# Return value: True, if only one command is specified. Otherwise false. Returns
#   undef, if something went wrong and prints a warning.
sub _are_commands_mutual_exclusive {
    if (! defined($_[0]) || ref($_[0]) ne 'HASH') {
        cluck('_are_commands_mutual_exclusive(): First parameter has to be a '.
            'reference to the parameter hash.');
        return undef();
    }
    my $params = $_[0];
    
    my $command_counter = 0;
    if (exists($params->{'append'})) {
        $command_counter++;
    }
    if (exists($params->{'check'})) {
        $command_counter++;
    }
    if (exists($params->{'delete'})) {
        $command_counter++;
    }
    if (exists($params->{'insert'})) {
        $command_counter++;
    }
    if (exists($params->{'replace'})) {
        $command_counter++;
    }
    # Command '-L, --list [chain]' is ignored.
    # Command '-S, --list-rules [chain]' is ignored.
    if (exists($params->{'flush'})) {
        $command_counter++;
    }
    if (exists($params->{'zero'})) {
        $command_counter++;
    }
    if (exists($params->{'new-chain'})) {
        $command_counter++;
    }
    if (exists($params->{'delete-chain'})) {
        $command_counter++;
    }
    if (exists($params->{'policy'})) {
        $command_counter++;
    }
    if (exists($params->{'rename-chain'})) {
        $command_counter++;
    }

    return ($command_counter == 1);
}



# Does some plausibility checks to find faulty lines.
#
# Parameter: reference to a hash containing the parameters
# Return value: True, if all pausibility checks were passed. Otherwise false.
#   Returns undef, if something went wrong and prints a warning.
sub _plausibility_checks {
    if (! defined($_[0]) || ref($_[0]) ne 'HASH') {
        cluck('_plausibility_checks(): First parameter has to be a reference '.
            'to the parameter hash.');
        return undef();
    }
    my $params = $_[0];

    my $tmp;
    # Verify, that only one command was specified.
    $tmp = _are_commands_mutual_exclusive($params);
    if (! defined($tmp)) {
        cluck('_plausibility_checks(): Call to '.
            '_are_commands_mutual_exclusive() was not successful.');
        return undef();
    }
    if (! $tmp) {
        return 0;
    }

    return 1;
}



# Adds missing declarations. Some parameters get declarations by iptables-save.
#
# FIXME: Is this necessary?
#
# Parameter:
#   * reference to a hash containing the parameters
# Return value: the parameters in the hash are modified; returns undef, if
#   something went wrong and prints a warning
sub _add_missing_declarations {
    if (! defined($_[0]) || ref($_[0]) ne 'HASH') {
        cluck('_add_missing_declarations(): First parameter has to be a '.
            'reference to the parameter hash.');
        return undef();
    }
    my $params = $_[0];
    
    # Nothing to do at the moment.
    
    return 0;
}



# Apply the current rule to the current rule set.
#
# Parameters:
#   * a reference to the current rule set
#   * a reference to the parsed iptables parameters
# Return value: the rule set is manipulated; returns undef, if something went
#   wrong and prints a warning
sub _apply_rule {
    d('_apply_rule()', 1, 'Applying rule.');
    if (! defined($_[0]) || ref($_[0]) ne 'HASH') {
        cluck('_apply_rule(): First parameter has to be a reference to the '.
            'rule set hash.');
        return undef();
    }
    if (! defined($_[1]) || ref($_[1]) ne 'HASH') {
        cluck('_apply_rule(): Second parameter has to be a reference to the '.
            'parameter hash.');
        return undef();
    }
    my $rule_set = $_[0];
    my $params = $_[1];

    my $tmp;
    my $table_name; # name of the table (used for messages)
    my $table; # reference to table
    my $sources = []; # reference to array with source IP addresses
    my $sources_inverse = ''; # use inverse ('!') for all source addresses
    my $destinations = []; # reference to array with destination IP addresses
    # use inverse ('!') for all destination addresses
    my $destinations_inverse = '';
    # an array of references to the parsed iptables parameters
    my @params_array = ();
    
    # Select the correct table. Default is TABLE_FILTER.
    if (exists($params->{'table'})) {
        $table_name = (split(' ', $params->{'table'}->[0]))[1];
        d('_apply_rule(): ()', 5, 'Table is \''.$table_name.'\'.');
        $table = $rule_set->{$table_name};
    } else {
        # default table
        $table_name = TABLE_FILTER;
        d('_apply_rule(): ()', 5, 'Table is \''.$table_name.'\'.');
        $table = $rule_set->{TABLE_FILTER()};
    }
    if (! defined($table)) {
        # Note: iptables-save knows about the order, how the tables have been
        # accessed. It works like a FILO (Fist In Last Out). That means, the
        # first table, that was somehow accessed, will be output last. This
        # has to be considered, when additional tables are implemented, because
        # the order of accessing the tables has to be remembered.
        cluck('_apply_rule(): Not implemented yet (handling of table \''.
            $params->{'table'}->[0].'\').');
        return undef();
    }
    
    # Some parameters will get additional declarations by iptables-save.
    if (! defined(_add_missing_declarations($params))) {
        cluck('_apply_rule(): Call to _add_missing_declarations() was not '.
            'successful.');
        return undef();
    }
    
    # Before the rule can be applied, look for source and destination
    # addresses, so that the rule can be handled properly. That means, one line
    # may expand to several lines.
    if (exists($params->{'source'})) {
        $tmp = _get_arguments($params->{'source'}->[0]);
        if (! defined($tmp)) {
            cluck('_apply_rule(): Call to _get_arguments() was not '.
                'successful.');
            return undef();
        }
        # Is the source inverse?
        if (index($params->{'source'}->[0], '!') == 0) {
            # Inversion of several addresses is not allowed.
            if (index($tmp->[0], ',') > -1) {
                cluck('_apply_rule(): Inversion of several addresses is not '.
                    'allowed: \''.$params->{'source'}->[0].'\'');
                return undef();
            }
            $sources_inverse = '! ';
        } else {
            $sources_inverse = '';
        }
        # Get the IP addresses.
        $sources = _get_ip_addresses($tmp->[0]);
        if (! defined($sources)) {
            cluck('_apply_rule(): Call to _get_ip_addresses() was not '.
                'successful.');
            return undef();
        }
    }
    if (exists($params->{'destination'})) {
        $tmp = _get_arguments($params->{'destination'}->[0]);
        if (! defined($tmp)) {
            cluck('_apply_rule(): Call to _get_arguments() was not '.
                'successful.');
            return undef();
        }
        # Is the destination inverse?
        if (index($params->{'destination'}->[0], '!') == 0) {
            # Inversion of several addresses is not allowed.
            if (index($tmp->[0], ',') > -1) {
                cluck('_apply_rule(): Inversion of several addresses is not '.
                    'allowed: \''.$params->{'destination'}->[0].'\'');
                return undef();
            }
            $destinations_inverse = '! ';
        } else {
            $destinations_inverse = '';
        }
        # Get the IP addresses.
        $destinations = _get_ip_addresses($tmp->[0]);
        if (! defined($destinations)) {
            cluck('_apply_rule(): Call to _get_ip_addresses() was not '.
                'successful.');
            return undef();
        }
    }
    # If there are source or destination addresses, generate one line for each
    # address combination. For each source apply all destinations.
    if (scalar(@{$sources}) && scalar(@{$destinations})) {
        # Found source and destination IP addresses.
        my $clone;
        for my $s (@{$sources}) {
            for my $d (@{$destinations}) {
                $clone =  { ( %{$params} ) }; # We do not need a deep copy.
                # The IP address "anywhere", that has a subnet mask length of
                # zero, is not output, except it is inverted.
                if (($s =~ m/\/0$/) && ($sources_inverse eq '')) {
                    delete($clone->{'source'});
                } else {
                    $clone->{'source'} = [ $sources_inverse.'-s '.$s ];
                }
                if (($d =~ m/\/0$/) && ($destinations_inverse eq '')) {
                    delete($clone->{'destination'});
                } else {
                    $clone->{'destination'} =
                        [ $destinations_inverse.'-d '.$d ];
                }
                push(@params_array, $clone);
            }
        }
    } elsif (scalar(@{$sources}) && ! scalar(@{$destinations})) {
        # Found source IP addresses.
        my $clone;
        for my $s (@{$sources}) {
            $clone =  { ( %{$params} ) }; # We do not need a deep copy.
            # The IP address "anywhere", that has a subnet mask length of zero,
            # is not output, except it is inverted.
            if (($s =~ m/\/0$/) && ($sources_inverse eq '')) {
                delete($clone->{'source'});
            } else {
                $clone->{'source'} = [ $sources_inverse.'-s '.$s ];
            }
            push(@params_array, $clone);
        }
    } elsif (! scalar(@{$sources}) && scalar(@{$destinations})) {
        # Found destination IP addresses.
        my $clone;
        for my $d (@{$destinations}) {
            $clone =  { ( %{$params} ) }; # We do not need a deep copy.
            # The IP address "anywhere", that has a subnet mask length of
            # zero, is not output, except it is inverted.
            if (($d =~ m/\/0$/) && ($destinations_inverse eq '')) {
                delete($clone->{'destination'});
            } else {
                $clone->{'destination'} = [ $destinations_inverse.'-d '.$d ];
            }
            push(@params_array, $clone);
        }
    } else {
        # Neither source nor destination addresses found.
        push(@params_array, $params);
    }
    
    # Chain management
    # All commands should be mutual exclusive and that has been checked by the
    # plausibility check.
    # Command '-L, --list [chain]' is ignored.
    # Command '-S, --list-rules [chain]' is ignored.
    my $rules; # reference to the rules of a chain
    my $chain_name; # name of a chain
    my $rule_number; # number of a rule
    my $args; # reference to arguments of a parameter
    foreach my $param_ref (@params_array) {
        if (exists($param_ref->{'append'})) {
            # -A, --append chain
            $tmp = _get_arguments($param_ref->{'append'}->[0]);
            if (! defined($tmp)) {
                cluck('_apply_rule(): Call to _get_arguments() was not '.
                    'successful.');
                return undef();
            }

            $chain_name = $tmp->[0];
            if (! exists($table->{KEY_RULES()}->{$chain_name})) {
                cluck('_apply_rule(): Unknown chain was used with command '.
                    '\'append\': table is \''.$table_name.'\', chain is \''.
                    $chain_name.'\'');
                return undef();
            }
            $rules = $table->{KEY_RULES()}->{$chain_name};
            push(@{$rules}, $param_ref);
        } elsif (exists($param_ref->{'check'})) {
            cluck('_apply_rule(): Not implemented yet: \'check\'.');
            return undef();
            # -C, --check chain
        } elsif (exists($param_ref->{'delete'})) {
            cluck('_apply_rule(): Not implemented yet: \'delete\'.');
            return undef();
            # -D, --delete chain
            # -D, --delete chain rulenum
        } elsif (exists($param_ref->{'insert'})) {
            # -I, --insert chain [rulenum]
            $args = _get_arguments($param_ref->{'insert'}->[0]);
            if (! defined($args)) {
                cluck('_apply_rule(): Call to _get_arguments() was not '.
                    'successful.');
                return undef();
            }
            $chain_name = $args->[0];
            if (! exists($table->{KEY_RULES()}->{$chain_name})) {
                cluck('_apply_rule(): Unknown chain was used with command '.
                    '\'insert\': table is \''.$table_name.'\', chain is \''.
                    $chain_name.'\'');
                return undef();
            }
            $rules = $table->{KEY_RULES()}->{$chain_name};
            $rule_number = $args->[1];
            $rule_number ||= 1; # defaults to one
            if ($rule_number > (scalar(@{$rules}) + 1)) {
                # iptables accepts only a rule number, that is at most one after
                # the last rule in the chain.
                cluck('_apply_rule(): Rule number \''.$rule_number.'\' is too '.
                    'big; rule will not be inserted.');
                return undef();
            } elsif ($rule_number < 1) {
                # The rule number is not allowed to be smaller than the first
                # rule.
                cluck('_apply_rule(): Rule number \''.$rule_number.'\' is too '.
                    'small; rule will not be inserted.');
                return undef();
            }
            # Substitute 'insert' with 'append'
            delete($param_ref->{'insert'});
            $param_ref->{'insert'} = [ '-A '.$chain_name ];
            # Insert rule at the given position.
            # Remember: Arrays start at 0 and rule numbers at 1.
            splice(@{$rules}, ($rule_number - 1), 0, $param_ref);
        } elsif (exists($param_ref->{'replace'})) {
            cluck('_apply_rule(): Not implemented yet: \'replace\'.');
            return undef();
            # -R, --replace chain rulenum
        } elsif (exists($param_ref->{'flush'})) {
            # -F, --flush [chain]
            $tmp = _get_arguments($param_ref->{'flush'}->[0]);
            if (! defined($tmp)) {
                cluck('_apply_rule(): Call to _get_arguments() was not '.
                    'successful.');
                return undef();
            }
            $chain_name = $tmp->[0];
            if (! defined($chain_name)) {
                # Flush all chains.
                foreach (keys(%{$table->{KEY_RULES()}})) {
                    $table->{KEY_RULES()}->{$_} = [];
                }
            } else {
                # Flush one chain.
                if (! exists($table->{KEY_RULES()}->{$chain_name})) {
                    cluck('_apply_rule(): Unknown chain was used with command '.
                        '\'flush\': table is \''.$table_name.'\', chain is \''.
                        $chain_name.'\'');
                    return undef();
                }
                $table->{KEY_RULES()}->{$chain_name} = [];
            }
        } elsif (exists($param_ref->{'zero'})) {
            cluck('_apply_rule(): Not implemented yet: \'zero\'.');
            return undef();
            # -Z, --zero [chain [rulenum]]
        } elsif (exists($param_ref->{'new-chain'})) {
            # -N, --new-chain chain
            # FIXME: What happens, if a chain is specified a second time?
            $tmp = _get_arguments($param_ref->{'new-chain'}->[0]);
            if (! defined($tmp)) {
                cluck('_apply_rule(): Call to _get_arguments() was not '.
                    'successful.');
                return undef();
            }
            $chain_name = $tmp->[0];
            # Add new chain name to the list of chains.
            push(@{$table->{KEY_CHAINS()}}, $chain_name);
            # Prepare e new array reference in the rules hash.
            $table->{KEY_RULES()}->{$chain_name} = [];
        } elsif (exists($param_ref->{'delete-chain'})) {
            # -X, --delete-chain [chain]
            $tmp = _get_arguments($param_ref->{'delete-chain'}->[0]);
            if (! defined($tmp)) {
                cluck('_apply_rule(): Call to _get_arguments() was not '.
                    'successful.');
                return undef();
            }
            $chain_name = $tmp->[0];
            if (! defined($chain_name)) {
                # Delete all user-defined chains.
                # First check, if all chains are empty.
                foreach (@{$table->{KEY_CHAINS()}}) {
                    if (scalar(@{$table->{KEY_RULES()}->{$_}}) > 0) {
                        cluck('_apply_rule(): Chain \''.$_.'\' still contains '.
                            'rules. Will not delete all user-defined chains '.
                            'in table \''.$table_name.'\'.');
                        return undef();
                    }
                }
                # Than delete the rule data for every chain...
                foreach (@{$table->{KEY_CHAINS()}}) {
                    delete($table->{KEY_RULES()}->{$_});
                }
                # ... and the chains itself.
                $table->{KEY_CHAINS()} = [];
            } else {
                # Delete one user-defined chain.
                if (! exists($table->{KEY_RULES()}->{$chain_name})) {
                    cluck('_apply_rule(): Unknown chain was used with command '.
                        '\'delete-chain\': table is \''.$table_name.
                        '\', chain is \''.$chain_name.'\'');
                    return undef();
                }
                delete($table->{KEY_RULES()}->{$chain_name});
                # Since it is an array, the remaining chains have to be grepped.
                my @remaining_chains =
                    grep(! m/^$chain_name$/, @{$table->{KEY_CHAINS()}});
                $table->{KEY_CHAINS()} = \@remaining_chains;
            }
        } elsif (exists($param_ref->{'policy'})) {
            # -P, --policy chain target
            $args = _get_arguments($param_ref->{'policy'}->[0]);
            if (! defined($args)) {
                cluck('_apply_rule(): Call to _get_arguments() was not '.
                    'successful.');
                return undef();
            }
            $chain_name = $args->[0];
            my $target_name = $args->[1];
            # Only built-in chains can have targets.
            my $found = 0;
            foreach (@{$table->{KEY_DEFAULT_CHAINS()}}) {
                if ($chain_name eq $_) {
                    $found = 1;
                    last;
                }
            }
            if (! $found) {
                cluck('_apply_rule(): The policy can only be set for built-in '.
                    'chains. Wrong chain is \''.$chain_name.'\'.');
                return undef();
            }
            # A target is one of the following special values: ACCEPT, DROP,
            # QUEUE, RETURN.
            $found = 0;
            foreach (TARGET_ACCEPT, TARGET_DROP, TARGET_QUEUE, TARGET_RETURN) {
                if ($target_name eq $_) {
                    $found = 1;
                    last;
                }
            }
            if (! $found) {
                cluck('_apply_rule(): The target for a policy can only be a '.
                    'special value (ACCEPT, DROP, QUEUE, RETURN). Wrong '.
                    'target is \''.$target_name.'\'.');
                return undef();
            }
            # Set new policy.
            $table->{KEY_DEFAULT_POLICY()}->{$chain_name} = $target_name;
        } elsif (exists($param_ref->{'rename-chain'})) {
            cluck('_apply_rule(): Not implemented yet: \'rename-chain\'.');
            return undef();
            # -E, --rename-chain old-chain new-chain
        } else {
            # Oops! This should not happen.
            my @text = map { ">>$_<< => >>".join('<< | >>',
                @{$param_ref->{$_}})."<<" } keys(%{$param_ref});
                cluck('_apply_rule(): No command found in parameters! '.
                    "\n    ".join("\n    ", @text));
                return undef();
        }
    }
    
    return 0;
}



# Generates a string consisting of all parameters in an order like iptables-save
# outputs them.
#
# Parameter: a reference to the parsed iptables parameters
# Return value: string, that consists all parameters in an order like 
#   iptables-save outputs; returns undef, if something went wrong and prints a
#   warning
sub _get_parameters_string {
    if (! defined($_[0]) || ref($_[0]) ne 'HASH') {
        cluck('_get_parameters_string(): First parameter has to be a '.
            'reference to the parameter hash.');
        return undef();
    }
    my $params = $_[0];
    
    my $result = '';
    my $i;
    foreach (@_argument_order) {
        if (exists($params->{$_})) {
            # Add space between parameters.
            if (length($result) > 0) {
                $result .= ' ';
            }
            # We have to join here, because we might have at least several match
            # extensions.
            $result .= join(' ', @{$params->{$_}});
        }
    }
    d('_get_parameters_string()', 3, 'Generated string: \''.$result.'\'');
    
    return $result;
}



# Generates an output, that is compatible with iptables-save.
#
# Parameter: a reference to the current rule set
# Return value: a reference to an array containing the output; returns undef, if
#   something went wrong and prints a warning
sub _generate_output {
    if (! defined($_[0]) || ref($_[0]) ne 'HASH') {
        cluck('_generate_output(): First parameter has to be a reference to '.
            'the rule set hash.');
        return undef();
    }
    my $rule_set = $_[0];    

    my @tables_processed = TABLE_ORDER_FOR_OUTPUT;
    my $table; # reference to a table
    my $table_name;
    my @rules;
    my @result = ();
    my $parameter_string;
    
    foreach (@tables_processed) {
        $table_name = $_;
        $table = $rule_set->{$_};
        if (! defined($table)) {
            cluck('_generate_output(): Table \''.$table_name.
                '\' does not exists. Is it implemented?');
            return undef();
        }
        
        # table definition
        push(@result, '*'.$table_name."\n");
        # default chain definitions first
        foreach (@{$table->{KEY_DEFAULT_CHAINS()}}) {
            push(@result, ':'.$_.' '.$table->{KEY_DEFAULT_POLICY()}->{$_}.
                ' [0:0]'."\n");
        }
        # user-defined chains
        foreach (sort(@{$table->{KEY_CHAINS()}})) {
            push(@result, ':'.$_.' - [0:0]'."\n");
        }
        # rules for the default chains
        foreach (@{$table->{KEY_DEFAULT_CHAINS()}}) {
            foreach (@{$table->{KEY_RULES()}->{$_}}) {
                $parameter_string = _get_parameters_string($_);
                if (! defined($parameter_string)) {
                    cluck('_generate_output(): Call to '.
                        '_get_parameters_string() was not successful.');
                    return undef();
                }
                push(@result, $parameter_string."\n");
            }
        }
        # rules for the user-defined chains
        foreach (sort(@{$table->{KEY_CHAINS()}})) {
            foreach (@{$table->{KEY_RULES()}->{$_}}) {
                $parameter_string = _get_parameters_string($_);
                if (! defined($parameter_string)) {
                    cluck('_generate_output(): Call to '.
                        '_get_parameters_string() was not successful.');
                    return undef();
                }
                push(@result, $parameter_string."\n");
            }
        }
        
        push(@result, 'COMMIT'."\n");
    }
    
    return \@result;
}



# Generates an output, that is compatible with iptables-save and can be used
# with iptables-restore. That applies to ip6tables-save and ip6tables-restore,
# too. Note that both IP versions are supported, but you have to specify the
# version, if it is IPv6, because the version defaults to IPv4 normally. This is
# used for the resolution of DNS names, for example.
#
# This function is used to sort the command line arguments used with iptables,
# so that the arguments have the same order like iptables-save would generate
# it. Additionally the rules are applied as expected and some meta information
# is derived from the given lines to generate an output, that is compatible with
# the output from iptables-save.
#
# Note, that only calls to iptables and ip6tables are accepted, so that empty
# lines and comments have to be removed, if they exist in the original input.
#
# Parameter:
#   * reference to an array of iptables commands
#   * string, optionally specifying the version of IP, 'IPv4' (default) or
#       'IPv6'
# Return value: a reference to an array containing lines compatible to
#   iptables-save; returns undef, if something went wrong and prints a warning
sub generate_output {
    my $commands = shift();
    if (ref($commands) ne 'ARRAY') {
        cluck('generate_output(): First argument is not a reference to an '.
            'array.');
        return undef();
    }
    my $version = shift() // VERSION_IP_V4;
    if ($version ne VERSION_IP_V4 && $version ne VERSION_IP_V6) {
        cluck('generate_output(): Second argument does not specify an IP '.
            'version: \''.$version.'\'.');
        return undef();
    }
    
    # rule set with tables and chains
    my $rule_set = _init_rule_set($version);
    if (! defined($rule_set)) {
        cluck('generate_output(): Call to _init_rule_set() was not '.
            'successful.');
        return undef();
    }

    # parameters of a call to iptables
    my $parameters;
    my $result_checks;
    for my $line (@{$commands}) {
        # Get the parameters.
        chomp($line);
        $parameters = _get_parameters($line);
        if (! defined($parameters)) {
            cluck('generate_output(): Call to _get_parameters() was not '.
                'successful. Line is \''.$line.'\'.');
            return undef();
        }
        if (get_debug() > 4) {
            my @debug_text = map { ">>$_<< => >>".
                join('<< | >>', @{$parameters->{$_}})."<<" }
                keys(%{$parameters});
            d('generate_output()', 5, 'Found parameters: '."\n    ".
                join("\n    ", @debug_text));
        }
        
        # Verify some special cases.
        $result_checks = _plausibility_checks($parameters);
        if (! defined($result_checks)) {
            cluck('generate_output(): Call to _plausibility_checks() was not '.
                'successful. Line is \''.$line.'\'.');
            return undef();
        }
        if (! $result_checks) {
            my @text = map { ">>$_<< => >>".
                join('<< | >>', @{$parameters->{$_}})."<<" }
                keys(%{$parameters});
            # FIXME: Which check was missed? -Return a string?
            cluck('generate_output(): The plausibility checks where not '.
                'passed: '."\n    ".join("\n    ", @text));
            return undef();
        }
        
        # Apply the current rule to the rule set.
        if (! defined(_apply_rule($rule_set, $parameters))) {
            cluck('generate_output(): Call to _apply_rule() was not '.
                'successful. Line is \''.$line.'\'.');
            return undef();
        }
    }

    # Generate output compatible to iptables-save.
    my $output = _generate_output($rule_set);
    if (! defined($output)) {
        cluck('generate_output(): Call to _generate_output() was not '.
            'successful.');
        return undef();
    }

    return $output;
}



1;
