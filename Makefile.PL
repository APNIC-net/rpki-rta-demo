use strict;
use warnings;

use ExtUtils::MakeMaker;
use ExtUtils::MakeMaker::Config;

my $output = WriteMakefile(
    NAME           => 'APNIC::RPKI::CA',
    AUTHOR         => 'Software <software@apnic.net>',
    LICENSE        => 'bsd',
    VERSION_FROM   => 'lib/APNIC/RPKI/CA.pm',
    META_MERGE     => {
        resources => {
            repository => 'https://github.com/APNIC-net/rpki-rta'
        }
    },
    EXE_FILES      => [ qw(bin/setup-ca bin/issue-ee
                           bin/sign-rta bin/verify-rta
                           bin/show-ee bin/resign-rta
                           bin/show-rta) ],
    PREREQ_PM      => { 'Test::More'             => 0,
                        'HTTP::Daemon'           => 0,
                        'YAML'                   => 0,
                        'LWP::UserAgent'         => 0,
                        'List::MoreUtils'        => 0,
                        'IO::Capture::Stderr'    => 0, }
);

1;
