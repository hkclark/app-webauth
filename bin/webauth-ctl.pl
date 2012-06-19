#!/usr/bin/env perl

use strict;
use warnings;

our $VERSION = '0.01';

=head1 NAME

webauth-ctl.pl - Controller script for App::Webauth

=head1 ABSTRACT

Controller script to start, stop, clear, list and purge iptables/ipsets and session entries.

=head1 SYNOPSIS

 webauth-ctl.pl [-f webauth.cfg] [-l log4perl.cfg] ACTION

=cut

use sigtrap qw(die untrapped normal-signals);

use Pod::Usage qw(pod2usage);
use FindBin qw($Bin $Script);
use lib "$Bin/../lib";

use Log::Log4perl qw(:easy);
use Getopt::Long qw(GetOptions);
use Try::Tiny;
use App::Webauth;
use App::Webauth::LockHandle;

$ENV{PATH} = '/sbin:/bin:/usr/sbin:/usr/bin';

select(STDERR) and $| = 1;
select(STDOUT) and $| = 1;

#####################################################################
# put scriptname in process table instead of plain 'perl'
# but safe the pathname for pod2usage, sigh
#####################################################################
my $pathname = $0;
$0 = $Script;

#####################################################################
# handle cmdline options and args
#####################################################################

my $cfg_file =
     $ENV{APP_WEBAUTH_CONFIG}
  || -e "$Bin/../etc/local/config.pl" && "$Bin/../etc/local/config.pl"
  || -e "$Bin/../etc/config.pl" && "$Bin/../etc/config.pl";

my $log4perl =
     $ENV{APP_WEBAUTH_LOG4PERL}
  || -e "$Bin/../etc/local/log4perl.conf" && "$Bin/../etc/local/log4perl.conf"
  || -e "$Bin/../etc/log4perl.conf" && "$Bin/../etc/log4perl.conf";

GetOptions(
    'loggfile=s' => \$log4perl,
    'file=s'     => \$cfg_file,
  )
  or pod2usage(
    {
        -input   => $pathname,
        -exitval => 1,
        -verbose => 1,
        -output  => \*STDERR
    }
  );

if ( $log4perl && -f $log4perl ) {
    Log::Log4perl->init($log4perl);
}
else {
    Log::Log4perl->easy_init($DEBUG);
}

=head1 OPTIONS

=over 4

=item B<--file> webauth.cfg

App::Webauth config file. By default

    $ENV{APP_WEBAUTH_CONFIG} ||
    $Bin/../etc/local/config.pl ||
    $Bin/../etc/config.pl

=item B<--logg> log4perl.cfg

Log::Log4perl config file. By default

    $ENV{APP_WEBAUTH_LOG4PERL}   ||
    $Bin/../etc/local/log4perl.conf ||
    $Bin/../etc/log4perl.conf

=back

=cut

# dispatch table
my $actions = {
    start       => \&start_fw,
    stop        => \&stop_fw,
    start_clear => \&start_clear_fw,
    purge       => \&purge_sessions,
    status      => \&fw_status,
    clear       => \&clear_sessions,
    list        => \&list_sessions,
};

=head1 ARGUMENTS

One and only one ACTION is needed.

=over 4

=item B<start>

start the firewall, reload old sessions

=item B<stop>

stop the firewall, keep current sessions

=item B<purge>

purge idle sessions, periodically used by cron

=item B<start_clear>

start the firewall, flush old sessions

=item B<clear>

clear current sessions from iptables/ipsets and sessions dir

=item B<status>

check the firewall status

=item B<list>

list  sessions from iptables/ipsets and sessions dir

=back

=cut

my $action = shift;

pod2usage(
    {
        -input   => $pathname,
        -message => "ACTION missing\n",
        -exitval => 1,
        -output  => \*STDERR
    }
) unless $action;

pod2usage(
    {
        -input   => $pathname,
        -message => "ACTION '$action' not supported\n",
        -exitval => 1,
        -output  => \*STDERR
    }
) unless ( exists $actions->{$action} );

#####################################################################
# create App::Webauth object and run the requested ACTION
#####################################################################

DEBUG "create new Webauth object";
my $webauth = App::Webauth->new( cfg_file => $cfg_file );

my $lock_file = $webauth->cfg->{LOCK_FILE};

DEBUG "#################### ACTION $action START #######################";
my $exit_code = $actions->{$action}->($webauth);
DEBUG "#################### ACTION $action END   #######################";

exit $exit_code || 0;

#####################################################################
########################## end of main ##############################
#####################################################################

# define ACTIONS

sub start_fw {
    my $webauth = shift;

    # try 30s to get the lock or die
    my $lock_handle = App::Webauth::LockHandle->new(
        file     => $lock_file,
        shared   => 0,
        blocking => 1,
        timeout  => 30_000_000,
    ) or LOGDIE "Couldn't get the lock";

    DEBUG 'starting webauth firewall ...';
    $webauth->fw_start;

    return 0;
}

sub stop_fw {
    my $webauth = shift;

    # try 30s to get the lock or die
    my $lock_handle = App::Webauth::LockHandle->new(
        file     => $lock_file,
        shared   => 0,
        blocking => 1,
        timeout  => 30_000_000,
    ) or LOGDIE "Couldn't get the lock";

    DEBUG 'stopping webauth firewall ...';
    $webauth->fw_stop;

    return 0;
}

sub start_clear_fw {
    my $webauth = shift;

    # try 30s to get the lock or die
    my $lock_handle = App::Webauth::LockHandle->new(
        file     => $lock_file,
        shared   => 0,
        blocking => 1,
        timeout  => 30_000_000,
    ) or LOGDIE "Couldn't get the lock";

    DEBUG 'try to clear disk session records';
    $webauth->clear_sessions_from_disk;

    DEBUG 'starting webauth firewall ...';
    $webauth->fw_start;

    return 0;
}

sub purge_sessions {
    my $webauth = shift;

    DEBUG 'purging idle and malformed sessions ...';

    if ( defined $webauth->fw_status ) {

        my $lock_handle = App::Webauth::LockHandle->new(
            file     => $lock_file,
            shared   => 0,
            blocking => 0,
            try      => 3,
        ) or LOGDIE "Couldn't get the lock";

        $webauth->fw_purge_sessions;

    }
    else {

        # It's a hack, requestet by Bing, sigh.
        # Normally this is an error condition, but the cronjob
        # would fill the mailbox.
        WARN "Can't purge, firewall rules not loaded!";
        return 1;
    }

    return 0;
}

sub fw_status {
    my $webauth = shift;

    DEBUG 'check status of webauth firewall ...';

    my $ipset_entries = $webauth->fw_status;

    if ( defined $ipset_entries ) {
        print "OK, firewall running and $ipset_entries ipset entries loaded.\n";
        return 0;
    }
    else {
        print "NOT OK, firewall rules not loaded.\n";
        return 1;
    }
}

sub list_sessions {
    my $webauth = shift;

    DEBUG 'listing ipset members ...';

    print '-' x 80 . "\n";
    print "IPSET MEMBERS:\n";
    print '-' x 80 . "\n";

    my $ipset_members = $webauth->fw_list_sessions;

    if ( defined $ipset_members ) {
        foreach my $ip ( sort keys %$ipset_members ) {
            printf "%-15.15s|%-17.17s\n", $ip, $ipset_members->{$ip};
        }
    } else {
        print "Firewall stopped!\n";
    }

    print '-' x 80 . "\n";

    DEBUG 'listing webauth sessions ...';

    my @sessions;

    foreach my $key ( $webauth->list_sessions_from_disk ) {

        my $lock_handle = $webauth->get_session_lock_handle(
            key      => $key,
            blocking => 1,
            shared   => 1,
            timeout  => 1_000_000,    # 1_000_000 us = 1s
        );

        my $session = $webauth->read_session_handle($lock_handle);

        next unless $session;

        push @sessions,
          [
            $session->{IP}, $session->{STATE},
	    $session->{USERNAME}, $session->{USER_AGENT},
          ];
    }

    print "SESSIONS:\n";
    print '-' x 80 . "\n";
    printf "%-15.15s|%-12.12s|%-14.14s|%s\n",
      qw(IP STATE USERNAME USER_AGENT);
    foreach my $session_data (@sessions) {
        printf "%-15.15s|%-12.12s|%-14.14s|%-40.40s ...\n",
          @$session_data;
    }
    print '-' x 80 . "\n";

    return 0;
}

sub clear_sessions {
    my $webauth = shift;

    $webauth->clear_sessions_from_disk;

    $webauth->fw_clear_sessions if defined $webauth->fw_status;

    return 0;
}

=head1 AUTHOR

Karl Gaissmaier, C<< <gaissmai at cpan.org> >>

=head1 LICENSE AND COPYRIGHT

Copyright 2012 Karl Gaissmaier, all rights reserved.

This distribution is free software; you can redistribute it and/or modify it
under the terms of either:

a) the GNU General Public License as published by the Free Software
Foundation; either version 2, or (at your option) any later version, or

b) the Artistic License version 2.0.

=cut
