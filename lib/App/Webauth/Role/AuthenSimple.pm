package App::Webauth::Role::AuthenSimple;

use strict;
use warnings;

=head1 NAME

App::Webauth::Role::AuthenSimple - Authen::Simple adapter for App::Webauth

=cut

our $VERSION = '0.02';

use Log::Log4perl qw(:easy);
use Authen::Simple qw();
use Try::Tiny;

use Role::Basic;
requires qw(cfg);

my $authen_singleton;

=head1 DESCRIPTION

App::Webauth authentication is based on the pluggable Authen::Simple framework.

=head1 ROLES

=over

=item $webauth->build_authenticator()

Load the Authen::Simple Plugins as specified in config file and create the authenticator object. Die on error.

=cut

sub build_authenticator {
    my $self = shift;

    return 1 if $self->cfg->{MOCK_AUTHEN};

    my $authen_modules = $self->cfg->{AUTHEN_SIMPLE_MODULES} || {};

    LOGDIE "missing Authen::Simple modules in config file\n"
      unless %$authen_modules;

    ### use Authen::Simple::... modules
    #
    my @authen_simple_objects;
    foreach my $module ( keys %$authen_modules ) {
        DEBUG("use $module");

        my $error;
        try { eval "use $module" } catch { $error = $_ };
        LOGDIE $error if $error;

        # create authen_simple_obj and push it to the modules array
        my $authen_obj = $module->new( $authen_modules->{$module} )
          or LOGDIE "Couldn't create $module object\n";

        push @authen_simple_objects, $authen_obj;
    }

    # and make the authen_simple object, see perldoc Authen::Simple

    DEBUG('build the authenticator object');

    $authen_singleton = Authen::Simple->new(@authen_simple_objects)
      or LOGDIE "Couldn't create the Authen::Simple object\n";

    return 1;
}

=item $webauth->authenticate($username, $password)

Call the authenticator object with credentials. Returns true on success and false on failure.

=cut

sub authenticate {
    my $self = shift;

    my $username = $_[0];

    DEBUG("try to authenticate user $username");

    if ( $self->cfg->{MOCK_AUTHEN} ) {

	DEBUG("mock authentication for user $username");

        return 1 if $username =~ m/^(mock|fake|foo|bar|baz)/i;
        return;
    }

    return $authen_singleton->authenticate(@_);
}

1;

=back

=head1 SEE ALSO

L<Authen::Simple>

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

# vim: sw=4
