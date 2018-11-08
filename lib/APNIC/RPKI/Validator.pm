package APNIC::RPKI::Validator;

use warnings;
use strict;

use APNIC::RPKI::CMS;
use APNIC::RPKI::OpenSSL;
use APNIC::RPKI::Utils qw(system_ad);
use File::Slurp qw(read_file);
use File::Temp qw(tempdir);
use Digest::SHA qw(sha256_hex);
use Net::CIDR::Set;
use Set::IntSpan;

sub new
{
    my ($class, $openssl) = @_;
    $openssl ||= APNIC::RPKI::OpenSSL->new();
    my $self = { openssl => $openssl };
    bless $self, $class;
    return $self;
}

sub validate_rta
{
    my ($self, $rta_raw, $ta, $content, $certs_only) = @_;

    my $openssl = $self->{'openssl'}->{'path'};
    
    my $ft = File::Temp->new();
    print $ft $rta_raw;
    $ft->flush();
    my $fn = $ft->filename();

    system("$openssl cms -inform DER -in $fn -verify -noverify -certsout /tmp/certs >/dev/null 2>&1");
    my @lines = read_file("/tmp/certs");
    my @certs;
    my @current_cert_lines;
    for my $line (@lines) {
        chomp $line;
        if ($line eq '-----BEGIN CERTIFICATE-----') {
            if (@current_cert_lines) {
                die "Failed to parse certificates";
            }
            push @current_cert_lines, $line;
        } elsif ($line eq '-----END CERTIFICATE-----') {
            push @current_cert_lines, $line;
            push @certs, (join "\n", @current_cert_lines);
            @current_cert_lines = ();
        } elsif (@current_cert_lines) {
            push @current_cert_lines, $line;
        } else {
            print "($line)\n";
            die "Failed to parse certificates (2)";
        }
    }

    if (not @certs) {
        die "No certificates found";
    }

    my $ipv4_set = Net::CIDR::Set->new({ type => 'ipv4' });
    my $ipv6_set = Net::CIDR::Set->new({ type => 'ipv6' });
    my $as_set = Set::IntSpan->new();
    my @skis;
    for my $cert (@certs) {
        my $cft = File::Temp->new();
        print $cft $cert;
        $cft->flush();
        my $cft_fn = $cft->filename();

        my @data = `$openssl x509 -in $cft_fn -text -noout`;
        if (grep { /CA:TRUE/ } @data) {
            # Don't load resources from non-EE certificates.
            next;
        }

        my $ski = $self->{'openssl'}->get_ski($cert);
        if (not $ski) {
            die "couldn't get ski for certificate";
        }
        push @skis, $ski;

        my ($ipv4, $ipv6, $as) =
            @{$self->{'openssl'}->get_resources($cert)};
        $ipv4_set->add($ipv4);
        $ipv6_set->add($ipv6);
        $as_set = $as_set->union($as);
        $self->{'certs'}->{$ski} = {
            ipv4 => $ipv4,
            ipv6 => $ipv6,
            as   => $as
        };
    }
    if ($certs_only) {
        return;
    }
 
    system("$openssl cms -inform DER -in $fn -verify -noverify -crlsout /tmp/crls >/dev/null 2>&1");
    @lines = read_file("/tmp/crls");
    my @crls;
    my @current_crl_lines;
    for my $line (@lines) {
        chomp $line;
        if ($line eq '-----BEGIN X509 CRL-----') {
            if (@current_crl_lines) {
                die "Failed to parse crlificates";
            }
            push @current_crl_lines, $line;
        } elsif ($line eq '-----END X509 CRL-----') {
            push @current_crl_lines, $line;
            push @crls, (join "\n", @current_crl_lines);
            @current_crl_lines = ();
        } elsif (@current_crl_lines) {
            push @current_crl_lines, $line;
        } else {
            print "($line)\n";
            die "Failed to parse CRLs (2)";
        }
    }

    if (not @crls) {
        die "No CRLs found";
    }

    my $ft_ta = File::Temp->new();
    for my $entry (@{$ta}) {
        print $ft_ta $entry;
        print $ft_ta "\n";
    }
    $ft_ta->flush();
    my $fn_ta = $ft_ta->filename();

    my $ft_output = File::Temp->new();
    my $fn_output = $ft_output->filename();

    my $debug = 0;
    eval { system_ad("$openssl cms -verify -crl_check_all -inform DER ".
              "-in $fn ".
              "-CAfile $fn_ta ".
              "-out $fn_output 2>&1",
              $debug); };
    if (my $error = $@) {
        system_ad("$openssl cms -verify -crl_check_all -inform DER ".
              "-in $fn ".
              "-CAfile $fn_ta ".
              "-out $fn_output 2>&1",
              1);
    }

    my $rta_data = read_file($fn_output);
    my $rta = APNIC::RPKI::RTA->new();
    $rta->decode($rta_data);

    my $digest = uc(sha256_hex($content));
    if ($digest ne uc($rta->digest())) {
        die "Digest mismatch.\n";
    }

    if (($rta->ipv4() and not $rta->ipv4()->is_empty()) xor (not $ipv4_set->is_empty())) {
        die "IPv4 resource mismatch.\n";
    }
    if ($rta->ipv4()) {
        if (not $rta->ipv4()->equals($ipv4_set)) {
            die "IPv4 resource mismatch.\n";
        }
    }

    if (($rta->ipv6() and not $rta->ipv6()->is_empty()) xor (not $ipv6_set->is_empty())) {
        die "IPv6 resource mismatch.\n";
    }
    if ($rta->ipv6()) {
        if (not $rta->ipv6()->equals($ipv6_set)) {
            die "IPv6 resource mismatch.\n";
        }
    }

    if (($rta->asn() and not $rta->asn()->is_empty()) xor (not $as_set->empty())) {
        die "ASN resource mismatch.\n";
    }
    if ($rta->asn()) {
        if (not $rta->asn()->equals($as_set)) {
            die "ASN resource mismatch.\n";
        }
    }

    my @rta_skis = sort @{$rta->subject_keys()};
    @skis = sort @skis;
    if (@skis != @rta_skis) {
        die "Subject key identifier mismatch ".
            "(RTA and EE certificates).";
    }
    for (my $i = 0; $i < @skis; $i++) {
        if ($skis[$i] ne (uc $rta_skis[$i])) {
            die "Subject key identifier mismatch ".
                "(RTA and EE certificates).";
        }
    }

    my $cms_parser = APNIC::RPKI::CMS->new();    
    my $cms_data = $cms_parser->decode($rta_raw);
    my @signature_skis = sort @{$cms_data->{'skis'}};

    if (@skis != @signature_skis) {
        die "Subject key identifier mismatch ".
            "(EE certificates and signatures).";
    }
    for (my $i = 0; $i < @skis; $i++) {
        if ($skis[$i] ne (uc $signature_skis[$i])) {
            die "Subject key identifier mismatch ".
                "(EE certificates and signatures).";
        }
    }

    return 1;
}

1;
