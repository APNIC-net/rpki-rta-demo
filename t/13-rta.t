#!/usr/bin/perl

use warnings;
use strict;

use File::Temp qw(tempdir);

use APNIC::RPKI::CA;
use APNIC::RPKI::RTA;
use MIME::Base64;
use Net::CIDR::Set;
use Set::IntSpan;

use Test::More tests => 3;

{
    my $ca_dir = tempdir(CLEANUP => 1);
    my $ca = APNIC::RPKI::CA->new(ca_path => $ca_dir);
    ok($ca, 'Got new CA');

    my $res = $ca->initialise('test');
    ok($res, 'Initialised CA successfully');

    my $req = $ca->get_ca_request('test');
    $ca->sign_ca_request($req, ['0.0.0.0/0', '::/0'], ['1-65535']);

    my $rta = APNIC::RPKI::RTA->new();
    $rta->version(0);
    $rta->subject_keys(['ABCD']);
    $rta->ipv4(Net::CIDR::Set->new({type => 'ipv4'}, '1.2.3.0-1.2.3.1'));
    $rta->ipv6(Net::CIDR::Set->new({type => 'ipv6'}, '::/1'));
    $rta->asn(Set::IntSpan->new('1-2,5,7-10'));
    $rta->algorithm('SHA256');
    $rta->digest('abcd');

    my $raw = $rta->encode();
    my $rta2 = APNIC::RPKI::RTA->new();
    $rta2->decode($raw);
    ok($rta->equals($rta2),
        'Decoded RTA matches input');
}

1;
