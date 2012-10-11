use strict;
use warnings;

use Test::More;

use_ok('App::Webauth');

my ( $webauth );

ok( $webauth = App::Webauth->new( cfg_file => 't/etc/ok.pl' ),
    'successfull parse t/etc/ok.pl' );

my ($cmds, $template, $tmpl_vars) ;
$tmpl_vars = { %{ $webauth->cfg->{IPTABLES} }, ipv4_aton => $webauth->can('ipv4_aton'), };

foreach my $template (
    qw( firewall/flush.tt
    firewall/filter.tt
    firewall/init.tt
    firewall/mangle.tt
    firewall/nat.tt )
  )
{
    ok( $webauth->{template}->process( $template, $tmpl_vars, \$cmds ),
        "rendering $template for IPSET version >= 4" );
    #diag $webauth->{template}->error;
}

# try the templates for older ipset versions
$tmpl_vars->{ipset_version} = 2;
foreach my $template (
    qw( firewall/flush.tt
    firewall/filter.tt
    firewall/init.tt
    firewall/mangle.tt
    firewall/nat.tt )
  )
{
    ok( $webauth->{template}->process( $template, $tmpl_vars, \$cmds ),
        "rendering $template for IPSET version < 4" );
    #diag $webauth->{template}->error;
}


# check error if some config values are missing
$tmpl_vars = { %{ $webauth->cfg->{IPTABLES} }, ipv4_aton => $webauth->can('ipv4_aton'), };
delete $tmpl_vars->{ipset_version};
$template = 'firewall/init.tt';
is( $webauth->{template}->process( $template, $tmpl_vars, \$cmds ), undef,
    "rendering $template without ipset_version throws error" );

$tmpl_vars = { %{ $webauth->cfg->{IPTABLES} }, ipv4_aton => $webauth->can('ipv4_aton'), };
delete $tmpl_vars->{inbound_open_dest_addrs};
$template = 'firewall/init.tt';
is( $webauth->{template}->process( $template, $tmpl_vars, \$cmds ), undef,
    "rendering $template without inbound_open_dest_addrs throws error" );

$tmpl_vars = { %{ $webauth->cfg->{IPTABLES} }, ipv4_aton => $webauth->can('ipv4_aton'), };
delete $tmpl_vars->{inbound_open_src_addrs};
$template = 'firewall/init.tt';
is( $webauth->{template}->process( $template, $tmpl_vars, \$cmds ), undef,
    "rendering $template without inbound_open_src_addrs throws error" );

$tmpl_vars = { %{ $webauth->cfg->{IPTABLES} }, ipv4_aton => $webauth->can('ipv4_aton'), };
delete $tmpl_vars->{redirect_port_ssl};
$template = 'firewall/nat.tt';
is( $webauth->{template}->process( $template, $tmpl_vars, \$cmds ), undef,
    "rendering $template without redirect_port_ssl throws error" );

done_testing(15);

