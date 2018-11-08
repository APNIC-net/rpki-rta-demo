#!/usr/bin/perl

use warnings;
use strict;

use File::Temp qw(tempdir);

use APNIC::RPKI::OpenSSL;
use APNIC::RPKI::CA;

use Test::More tests => 4;

{
    my $ca_dir = tempdir(CLEANUP => 1);
    my $ca = APNIC::RPKI::CA->new(ca_path => $ca_dir);
    ok($ca, 'Got new CA');

    my $res = $ca->initialise('test');
    ok($res, 'Initialised CA successfully');

    my $req = $ca->get_ca_request('test');
    $res = $ca->sign_ca_request($req, ['0.0.0.0/0', '::/0'], ['1-65535']);

    my $ca2_dir = tempdir(CLEANUP => 1);
    my $ca2 = APNIC::RPKI::CA->new(ca_path => $ca2_dir);
    ok($ca2, 'Got new CA');

    $res = $ca2->initialise('subtest');
    ok($res, 'Initialised CA successfully');

    my $req2 = $ca2->get_ca_request('subtest');
    my $res2 = $ca->sign_ca_request($req2, [], ['133000']);
}

1;
