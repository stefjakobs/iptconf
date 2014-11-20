package IptConf::DebugLib;

use strict;
use warnings;
use Exporter qw(import);
use Carp;



################################################################################
#
# Date: 2014-06-06
# Author:
# - Kilian Krause
# - Daniel Tiebler
#
################################################################################
#
# 2014-06-06, Daniel Tiebler
# * Changed package declaration to "IptConf::DebugLib".
#
# 2014-04-24, Daniel Tiebler
# * Error messages are printed to STDERR.
#
# 2014-04-24, Daniel Tiebler
# * Added get_debug() and get_verbose() to the export list.
#
# 2014-04-14, Kilian Krause, Daniel Tiebler
# * Refactored the code a little bit to save some instructions, if they are not
#   necessary.
#
# 2014-04-14, Daniel Tiebler
# * Added getters and setter for variables debug and verbose, that are hidden in
#   in a closure now. The rest of the code was adapted.
# * Added export of subroutines with module Exporter.
#
# 2014-04-11, Daniel Tiebler
# * Created package and copied all subroutines for debuging into the package.
#
################################################################################


 
# see manpage "perlmod"
BEGIN {
    # set the version for version checking
    our $VERSION = 0.01;
    # Functions and variables which are exported by default
    our @EXPORT = qw();
    # Functions and variables which can be optionally exported
    our @EXPORT_OK = qw(
        get_debug
        set_debug
        get_verbose
        set_verbose
        d
        v
        i
        e
    );
}



# closure for state variables
{
    my $debug = 0;
    my $verbose = 0;



    # Sets the current debug level.
    sub set_debug {
        my $value = shift(@_);
        if (! defined($value)) {
            croak("New value for debug level is undefined");
        }
        if ($value !~ m/^\d+$/) {
            croak("New value for debug level is not a positive number.");
        }
        $debug = $value;
    }



    # Sets the current verbose level.
    sub set_verbose {
        my $value = shift(@_);
        if (! defined($value)) {
            croak("New value for verbose level is undefined");
        }
        if ($value !~ m/^\d+$/) {
            croak("New value for verbose level is not a positive number.");
        }
        $verbose = $value;
    }



    # Gets the current debug level.
    sub get_debug {
        return $debug;
    }



    # Gets the current verbose level.
    sub get_verbose {
        return $verbose;
    }



} # end of closure



# debug output
sub d {
	# Debug print
	# $_[0] function calling
	# $_[1] prio
	# $_[2]... Text
    if (get_debug()) {
        my $queue = '';
        if (defined($_[0]) && $_[0] ne '') {
            $queue = '['.$_[0].'] ';
        }
        shift;
        my $prio = shift;
        if ($prio <= get_debug()) {
            print 'D'.$prio.': '.$queue."@_\n";
        }
    }
}



# verbose output
sub v {
    # verbose output print
    # $_[0] function calling
    # $_[1]... Text
    if (get_verbose()) {
        if (get_debug()) {
            my $queue = '';
            if (defined($_[0]) && $_[0] ne '') {
                $queue = '['.$_[0].'] ';
            }
            print 'V : '.$queue;
        }
        shift;
        print "@_\n";
    }
}



# informational output
sub i {
    # info output print
    # $_[0] function calling
    # $_[1]... Text
    if (get_debug()) {
        my $queue = '';
        if (defined($_[0]) && $_[0] ne '') {
            $queue = '['.$_[0].'] ';
        }
        print 'I : '.$queue;
    }
    shift;
    print "@_\n";
}



# error output
sub e {
    # error output print
    # $_[0]... Text
    print STDERR 'E : '."@_\n";
}



1;
