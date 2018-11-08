package APNIC::RPKI::OpenSSL;

use warnings;
use strict;

use File::Slurp qw(read_file);
use File::Temp;

use APNIC::RPKI::Utils qw(system_ad);

our $VERSION = '0.1';

sub new
{
    my $class = shift;

    my %args = @_;
    my $self = \%args;

    if (not $self->{'path'}) {
        $self->{'path'} = "/usr/local/ssl/bin/openssl";
    }

    bless $self, $class;
    return $self;
}

sub get_openssl_path
{
    my ($self) = @_;

    return $self->{'path'};
}

sub verify_cms
{
    my ($self, $input, $ca_cert) = @_;

    my $ft_input = File::Temp->new();
    print $ft_input $input;
    $ft_input->flush();
    my $fn_input = $ft_input->filename();

    my $ft_ca = File::Temp->new();
    print $ft_ca $ca_cert;
    $ft_ca->flush();
    my $fn_ca = $ft_ca->filename();

    my $ft_output = File::Temp->new();
    my $fn_output = $ft_output->filename();

    my $openssl = $self->get_openssl_path();
    system_ad("$openssl cms -verify -partial_chain -inform DER ".
              "-in $fn_input ".
              "-CAfile $fn_ca ".
              "-out $fn_output",
              $self->{'debug'});

    return read_file($fn_output);
}

sub get_ski
{
    my ($self, $cert) = @_;

    my $ft_cert = File::Temp->new();
    print $ft_cert $cert;
    $ft_cert->flush();
    my $fn_cert = $ft_cert->filename();

    my $openssl = $self->get_openssl_path();
    my (undef, $ski) = `$openssl x509 -in $fn_cert -text -noout | grep -A1 'Subject Key Identifier'`;
    $ski =~ s/\s*//g;
    $ski =~ s/://g;
    $ski = uc $ski;
    return $ski;
}

1;
