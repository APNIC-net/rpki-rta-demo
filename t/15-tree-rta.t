#!/usr/bin/perl

use warnings;
use strict;

use File::Temp qw(tempdir);

use APNIC::RPKI::OpenSSL;
use APNIC::RPKI::CA;
use APNIC::RPKI::RTA;
use APNIC::RPKI::Validator;
use Digest::SHA qw(sha256_hex);

use Test::More tests => 6;

{
    my $ca_dir = tempdir(CLEANUP => 1);
    my $ca = APNIC::RPKI::CA->new(ca_path => $ca_dir);
    ok($ca, 'Got new CA');

    my $res = $ca->initialise('test');
    ok($res, 'Initialised CA successfully');

    my $req = $ca->get_ca_request('test');
    $res = $ca->sign_ca_request($req, ['0.0.0.0/0', '::/0'], ['1-65535']);
    $ca->install_ca_certificate($res);
    $ca->cycle();
    my $ta = $res;

    my $ca2_dir = tempdir(CLEANUP => 1);
    my $ca2 = APNIC::RPKI::CA->new(ca_path => $ca2_dir);
    ok($ca2, 'Got new CA');

    my $res2 = $ca2->initialise('subtest');
    ok($res2, 'Initialised sub-CA successfully');

    my $req2 = $ca2->get_ca_request('test2');
    $res2 = $ca->sign_ca_request($req2, ['1.0.0.0/8', '::/1'], ['1-12000']);
    $ca2->install_ca_certificate($res2);
    $ca2->cycle();

    my $openssl = APNIC::RPKI::OpenSSL->new();

    my $ee = $ca2->issue_new_ee_certificate(['1.0.0.0/24']);
    my $ski = $openssl->get_ski($ee);

    my $data = 'asdf';
    my $hashed_data = sha256_hex($data);

    my $rta = APNIC::RPKI::RTA->new();
    $rta->version(0);
    $rta->subject_keys([$ski]);
    $rta->ipv4(Net::CIDR::Set->new({type => 'ipv4'}, '1.0.0.0/24'));
    $rta->algorithm('SHA256');
    $rta->digest($hashed_data);

    my $asn1_data = $rta->encode();
    my $cms = $ca2->sign_cms_rta($asn1_data, [$res2], [$ca->get_crl()]);
    
    my $validator = APNIC::RPKI::Validator->new();
    eval { $validator->validate_rta($cms, [$ee], 'asdf'); };
    ok($@, 'Failed to validate without trusted TA');
    
    eval { $validator->validate_rta($cms, [$ta], 'asdf'); };
    ok((not $@), 'Validated using trusted TA');
    diag $@ if $@;
}

1;
