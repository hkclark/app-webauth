#!/usr/bin/env perl

use strict;
use warnings;

our $VERSION = '0.01';

=head1 NAME

test-server.pl - single threaded HTTP/CGI testserver

=head1 DESCRIPTION

Don't use it in production, only base SSL/TLS and no FCGI supported.

=head1 SYNOPSIS

 test-server.pl [-ssl] [-p -port ] [- f webauth.cfg] [-l log4perl.cfg]

=head1 OPTIONS

=over 4

=item B<--ssl>

Listen for HTTPS requests.

=item B<--port> 3333

HTTP listen port. If not defined listens on port 3333 or 4433 if --ssl is defined.

=item B<--file> webauth.cfg

App::Webauth config file. If not defined looks for the following files

    $ENV{APP_WEBAUTH_CONFIG} ||
    $Bin/../etc/local/config.pl ||
    $Bin/../etc/config.pl

=item B<--logg> log4perl.cfg

Log::Log4perl config file. If not defined looks for the following files

    $ENV{APP_WEBAUTH_LOG4PERL}   ||
    $Bin/../etc/local/log4perl.conf ||
    $Bin/../etc/log4perl.conf

=back

=cut

use sigtrap qw(die untrapped normal-signals);

use FindBin qw($Bin $Script);
use lib "$Bin/../lib";

use Log::Log4perl qw(:easy);
use Getopt::Long qw(GetOptions);
use App::Webauth;
use App::Webauth::TestServer;

$ENV{PATH} = '/sbin:/bin:/usr/sbin:/usr/bin';

my $cfg_file =
     $ENV{APP_WEBAUTH_CONFIG}
  || -e "$Bin/../etc/local/config.pl" && "$Bin/../etc/local/config.pl"
  || -e "$Bin/../etc/config.pl" && "$Bin/../etc/config.pl";

my $log4perl =
     $ENV{APP_WEBAUTH_LOG4PERL}
  || -e "$Bin/../etc/local/log4perl.conf" && "$Bin/../etc/local/log4perl.conf"
  || -e "$Bin/../etc/log4perl.conf" && "$Bin/../etc/log4perl.conf";

my $ssl;
my $port;

GetOptions(
    'ssl'        => \$ssl,
    'loggfile=s' => \$log4perl,
    'file=s'     => \$cfg_file,
    'port=i'     => \$port,
) or usage();

unless ($port) {
    $ssl ? ($port = 4433) : ($port = 3333);
}

usage('configfile missing and APP_WEBAUTH_CONFIG not set')
  unless $cfg_file;

if ( $log4perl && -f $log4perl ) {
    Log::Log4perl->init($log4perl);
}
else {
    Log::Log4perl->easy_init($DEBUG);
}

DEBUG("create new App::Webauth object ...");
my $webauth = App::Webauth->new( cfg_file => $cfg_file );

DEBUG("create new App::Webauth::TestServer object ...");
my $server = App::Webauth::TestServer->new($ssl);
$server->port($port);
$server->host('127.0.0.1');

$server->{webauth}        = $webauth;
$server->{static_root} = $webauth->cfg->{DOCUMENT_ROOT};

INFO(   'You can connect the server on: '
      . ( $ssl ? 'https://' : 'http://' )
      . $server->host . ':'
      . $server->port );

$server->run;

sub usage {
    die "$Script [-ssl] [-p port] [-f webauth.cfg] [-l log4perl.cfg]\n";
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
