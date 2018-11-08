## rpki-rta

A proof-of-concept for constructing and validating resource-tagged
attestations (RTAs).  See
[https://tools.ietf.org/html/draft-michaelson-rpki-rta-00](https://tools.ietf.org/html/draft-michaelson-rpki-rta-00).

### Build

    $ docker build -t apnic/rpki-rta .

### Usage

    $ docker run -it apnic/rpki-rta /bin/bash

#### Basic RTA

    # setup-ca --name ca --resources 1.0.0.0/8
    # issue-ee --ca-name ca --resources 1.0.0.0/24
    # echo "asdf" > content
    # sign-rta --ca-name ca --path content --resources 1.0.0.0/24 --out rta
    # verify-rta --ca-name ca --path content --in rta
    Verification succeeded.

#### Digest mismatch

    # setup-ca --name ca --resources 1.0.0.0/8
    # issue-ee --ca-name ca --resources 1.0.0.0/24
    # echo "asdf" > content
    # sign-rta --ca-name ca --path content --resources 1.0.0.0/24 --out rta
    # echo "asdf2" > content
    # verify-rta --ca-name ca --path content --in rta
    Verification failed: Digest mismatch.

#### Resource mismatch

    # setup-ca --name ca --resources 1.0.0.0/8
    # issue-ee --ca-name ca --resources 1.0.0.0/24
    # echo "asdf" > content
    # sign-rta --ca-name ca --path content --resources 2.0.0.0/24 --out rta
    # verify-rta --ca-name ca --path content --in rta
    Verification failed: IPv4 resource mismatch.

#### No validation path for resources

    # setup-ca --name ca --resources 1.0.0.0/8
    # issue-ee --ca-name ca --resources 2.0.0.0/24
    # echo "asdf" > content
    # sign-rta --ca-name ca --path content --resources 2.0.0.0/24 --out rta
    # verify-rta --ca-name ca --path content --in rta
    Verification failure
    ... RFC 3779 resource not subset of parent's resources
    Verification failed: Command execution failed.

#### Incorrect TA for verification

    # setup-ca --name ca --resources 1.0.0.0/8
    # issue-ee --ca-name ca --resources 1.0.0.0/24
    # echo "asdf" > content
    # sign-rta --ca-name ca --path content --resources 1.0.0.0/24 --out rta
    # setup-ca --name ca2 --resources 1.0.0.0/8
    # verify-rta --ca-name ca2 --path content --in rta
    Verification failure
    ... unable to get local issuer certificate
    Verification failed: Command execution failed.

#### RTA with multiple signatures (one pass)

    # setup-ca --name ca --resources 1.0.0.0/8
    # issue-ee --ca-name ca --resources 1.0.0.0/24
    # setup-ca --name ca2 --resources 2.0.0.0/8
    # issue-ee --ca-name ca2 --resources 2.0.0.0/24
    # echo "asdf" > content
    # sign-rta --ca-name ca --ca-name ca2 \
               --path content --resources 1.0.0.0/24,2.0.0.0/24 \
               --out rta
    # verify-rta --ca-name ca --ca-name ca2 --path content --in rta
    Verification succeeded.

#### RTA with multiple signatures (two passes)

    # setup-ca --name ca --resources 1.0.0.0/8
    # issue-ee --ca-name ca --resources 1.0.0.0/24
    # setup-ca --name ca2 --resources 2.0.0.0/8
    # issue-ee --ca-name ca2 --resources 2.0.0.0/24
    # show-ee --ca-name ca2
    SKI:  3EF4E7B1135DE8A100DD0BBD4882E7F943C083EE
    IPv4: 2.0.0.0/24
    IPv6:
    ASN:
    # echo "asdf" > content
    # sign-rta --ca-name ca \
               --subject-key 3EF4E7B1135DE8A100DD0BBD4882E7F943C083EE \
               --path content --resources 1.0.0.0/24,2.0.0.0/24 \
               --out rta
    # verify-rta --ca-name ca --ca-name ca2 --path content --in rta
    Verification failed: IPv4 resource mismatch.
    # show-rta --in rta
    Version:    0
    Keys:       3EF4E7B1135DE8A100DD0BBD4882E7F943C083EE
                AD28CA615EC789B2B5C16C9C1FC33646152D7454
    Keys (sig): AD28CA615EC789B2B5C16C9C1FC33646152D7454
    IPv4:       1.0.0.0/24, 2.0.0.0/24
    IPv6:
    ASN:
    Algorithm:  SHA256
    Digest:     d1bc8d3ba4afc7e109612cb73acbdddac052c93025aa1f82942edabb7deb82a1
    # resign-rta --ca-name ca2 --in rta --out rta
    # show-rta --in rta
    Version:    0
    Keys:       3EF4E7B1135DE8A100DD0BBD4882E7F943C083EE
                AD28CA615EC789B2B5C16C9C1FC33646152D7454
    Keys (sig): 3EF4E7B1135DE8A100DD0BBD4882E7F943C083EE
                AD28CA615EC789B2B5C16C9C1FC33646152D7454
    IPv4:       1.0.0.0/24, 2.0.0.0/24
    IPv6:
    ASN:
    Algorithm:  SHA256
    Digest:     d1bc8d3ba4afc7e109612cb73acbdddac052c93025aa1f82942edabb7deb82a1
    # verify-rta --ca-name ca --ca-name ca2 --path content --in rta
    Verification succeeded.

#### RTA under tree

    # setup-ca --name ca --resources 1.0.0.0/8
    # setup-ca --name ca2 --resources 1.0.0.0/16 --parent-name ca
    # issue-ee --ca-name ca2 --resources 1.0.0.0/24
    # echo "asdf" > content
    # sign-rta --ca-name ca2 --path content --resources 1.0.0.0/24 --out rta
    # verify-rta --ca-name ca --path content --in rta
    Verification succeeded.

#### RTA provided out-of-band

    # verify-rta --ca-cert-path ./trusted.pem --path content --in rta
    Verification succeeded.

### Todo

   - Canonicalisation of signing input.
   - More CMS validity checks.
   - Documentation/tidying of code.

### License

See [LICENSE](./LICENSE).
