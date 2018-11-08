#!/usr/bin/perl

use warnings;
use strict;

use File::Temp qw(tempdir);

use APNIC::RPKI::OpenSSL;
use APNIC::RPKI::CA;

use Test::More tests => 5;

{
    my $openssl =
        APNIC::RPKI::OpenSSL->new(
            path => '/usr/bin/openssl'
        );
    ok($openssl, 'Got new OpenSSL object');
    is($openssl->get_openssl_path(),
        '/usr/bin/openssl',
        'Custom path is correct');

    $openssl =
        APNIC::RPKI::OpenSSL->new(
            debug => 1
        );
    ok($openssl, 'Got new OpenSSL object');

    my $ca_dir = tempdir(CLEANUP => 1);
    my $ca =
        APNIC::RPKI::CA->new(
            openssl => $openssl,
            ca_path => $ca_dir
        );
    $ca->initialise('test');
    $ca->cycle();

    my $cms = $ca->sign_cms('asdf');
    my $cert = '-----BEGIN X509 CERTIFICATE-----'."\n".
               $ca->get_ca_pem()."\n".
               '-----END X509 CERTIFICATE-----';
    my $res = eval { $openssl->verify_cms($cms, $cert) };
    ok((not $@), 'Verified CMS successfully');
    diag $@ if $@;
    is($res, 'asdf', 'Decoded CMS successfully');
}

1;
