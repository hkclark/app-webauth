use strict;
use warnings;

use Test::More;

use_ok('App::Webauth');

my ( $webauth, $session, $ip );

ok( $webauth = App::Webauth->new( cfg_file => 't/etc/ok.pl' ),
    'successfull parse t/etc/ok.pl' );

$webauth->clear_sessions_from_disk;

$session = _mk_session();
$ip     = $session->{IP};

my %lock_options = (
    key      => $ip,
    blocking => 0,
    shared   => 0,
);

{
    my $lock_handle;
    ok( $lock_handle = $webauth->get_session_lock_handle(%lock_options),
        'get session lock handle' );
    is( $webauth->read_session_handle($lock_handle),
        undef, 'read empty session' );
    ok( $webauth->write_session_handle( $lock_handle, $session ),
        'set session' );
    is_deeply( $webauth->read_session_handle($lock_handle),
        $session, 'check session' );
    ok( $webauth->write_session_handle( $lock_handle, $session ),
        'set same session again' );
    is_deeply( $webauth->read_session_handle($lock_handle),
        $session, 'check session again' );
}

ok( $webauth->clear_sessions_from_disk, 'cleared all sessions' ); 
is( $webauth->list_sessions_from_disk, 0, 'listed 0 sessions' );

foreach my $i (1 .. 50) {
    my $session = _mk_session();
    my $ip     = $session->{IP};

    my %lock_options = (
	key      => $ip,
	blocking => 0,
	shared   => 0,
    );

    my $lock_handle = $webauth->get_session_lock_handle(%lock_options);
}

is( $webauth->list_sessions_from_disk, 50, 'created/listed 50 sessions' );
ok( $webauth->clear_sessions_from_disk, 'cleared all sessions' );
is( $webauth->list_sessions_from_disk, 0, 'listed 0 sessions' );

done_testing(13);

sub _mk_session {
    my $subnet = int( rand(256) );
    my $host   = int( rand(256) );
    my $byte   = unpack( 'H2', int( rand(256) ) );

    my $ip  = "10.10.$subnet.$host";

    my $session = {
        IP            => $ip,
        STATE         => 'active',
        USERNAME      => 'test',
        USER_AGENT    => 'test',
    };

    return $session;
}

