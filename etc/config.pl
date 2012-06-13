use strict;
use warnings;
use subs qw(TRUE FALSE ON OFF YES NO);

return {

    ########################################################
    # available preset GLOBAL PACKAGE variables
    #
    # $APP_NAME = 'webauth';
    # $APP_DIR  = "$Bin/../";
    #
    ########################################################
    #  preset DEFAULTS
    ########################################################
    #
    #  DOCUMENT_ROOT         => "$APP_DIR/static",
    #  TEMPLATE_INCLUDE_PATH => "$APP_DIR/templates/local/:$APP_DIR/templates/orig",
    #
    #  RUN_USER              => 'wwwrun',
    #  RUN_GROUP             => 'www',
    #
    #  SESSIONS_DIR          => "/var/cache/$APP_NAME",
    #
    #  SSL_REQUIRED          => ON,
    #  SESSION_MAX           => 48 * 3600,    # 2d
    #  KEEP_OLD_STATE_PERIOD => 1 * 60 * 60,  # 1h
    #  IDLE_TIME             => 60 * 10,      # 10 min before set to idle
    #
    ########################################################
    #
    # please set your local values
    #

    ADMIN_SECRET => 'Secret',

    FINAL_REDIRECT_URL => 'https://my.front.server/splash/page',

    # authentication settings

    'AUTHEN_SIMPLE_MODULES' => {

      # you may stack the Authen::Simple modules
      #
      #  'Authen::Simple::Passwd' => {
      #      path   => '/etc/passwd',
      #  },

      #  'Authen::Simple::SSH' => {
      #      host   => 'ssh.your.domain',
      #  },

        'Authen::Simple::RADIUS' => {
            host   => 'radius.your.domain',
            secret => 'Secret',
            port   => 1812,
        },

    },

    # firewall rule setttings

    'IPTABLES' => {
        capture_if        => 'eth0',
        capture_ports     => [ 80, ],
        capture_ports_ssl => [ 443, ],

        # let your webserver listen there and send a HTTP redirect
        # to the webauth fcgi script, running under http/https

        redirect_port     => 8080,
        redirect_port_ssl => 4433,

	# Allow following clients/ranges/networks without authentication
	#
	# As input entry, you can add IP addresses,
	# CIDR blocks or network ranges to the ipset.
	#
	# CIDR blocks must be specified with all four octets,
	# e.g. 10.10.0.0/16, don't abbreviate it to 10.10/16! ( it's a bug in ipset(8) )
	# Network ranges can be specified in the format IP1-IP2, e.g. 192.168.1.3-192.168.1.19

        open_clients => [
            '192.168.0.1',
            '192.168.3.7-192.168.3.49',
            '10.10.0.0/16',

            # ...
        ],
      },

    # Languages in the message catalog and language specific templates.
    # You need for every language a separate template tree under
    # templates/local/view/[LANGUAGE]/...
    #
    I18N_LANGUAGES     => [ 'en', 'de', ],
                                   
    # fallback language if client languages aren't supported
    #
    I18N_FALLBACK_LANG => 'en',
                                       

    # translation of needed system messages
    # Every entry in I18N_LANGUAGES needs a translation
    #
    I18N_MSG_CATALOG => {
        msg_001 => {
            en => 'last session state was:',
            de => 'Status der letzten Sitzung war:',
        },

        msg_002 => {
            en => 'username or password is missing',
            de => 'Username oder Passwort fehlt',
        },

        msg_003 => {
            en => 'username or password is wrong',
            de => 'Username oder Passwort ist falsch',
        },

        msg_004 => {
            en => 'successfull logout',
            de => 'erfolgreich abgemeldet',
        },

        msg_005 => {
            en => 'admin_secret is wrong',
            de => 'Admin-Passwort ist falsch',
        },

        msg_006 => {
            en => 'Idle-session reestablished due to valid cookie.',
            de => 'Abgelaufene Sitzung durch gültiges Cookie erneuert.',
        },

      },

    # simple check whether this config file is locally adjusted
    # at least just delete this entry in order to run webauth
    BOILERPLATE => 1,
};

# vim: sw=2

