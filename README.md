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
    Algorithm:  SHA256
    Digest:     d1bc8d3ba4afc7e109612cb73acbdddac052c93025aa1f82942edabb7deb82a1
    Keys:       3EF4E7B1135DE8A100DD0BBD4882E7F943C083EE
                AD28CA615EC789B2B5C16C9C1FC33646152D7454
    IPv4:       1.0.0.0/24, 2.0.0.0/24
    IPv6:
    ASN:
    Signatures: AD28CA615EC789B2B5C16C9C1FC33646152D7454 1.0.0.0/24
    # resign-rta --ca-name ca2 --in rta --out rta
    # show-rta --in rta
    Version:    0
    Algorithm:  SHA256
    Digest:     d1bc8d3ba4afc7e109612cb73acbdddac052c93025aa1f82942edabb7deb82a1
    Keys:       3EF4E7B1135DE8A100DD0BBD4882E7F943C083EE
                AD28CA615EC789B2B5C16C9C1FC33646152D7454
    IPv4:       1.0.0.0/24, 2.0.0.0/24
    IPv6:
    ASN:
    Signatures: 3EF4E7B1135DE8A100DD0BBD4882E7F943C083EE 2.0.0.0/24
                AD28CA615EC789B2B5C16C9C1FC33646152D7454 1.0.0.0/24
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

#### RTA signed using out-of-band objects

To generate objects:

    $ docker run -it apnic/rpki.net
    # rpkic create_identity {name}
    (Send {name}.identity.xml to parent RPKI engine, e.g.
    rpki-testbed.apnic.net, and save response to response.xml.)
    # rpkic -i {name} configure_parent response.xml
    # rpkic configure_publication_client {name}.{parent-name}.repository-request.xml
    # rpkic -i {name} configure_repository {name}.repository-response.xml
    # rpkic -i {name} force_run_now
    # issue-ee {name} test-ee {resources}

After starting the RTA container:

    $ export RPKI_CONTAINER={rpki.net-container}
    $ export RTA_CONTAINER={rta-container}
    $ docker cp $RPKI_CONTAINER:/test-ee.pem .
    $ docker cp $RPKI_CONTAINER:/test-ee.pem.key .
    $ docker cp $RPKI_CONTAINER:/test-ee.pem.crl .
    $ docker cp test-ee.pem $RTA_CONTAINER:/
    $ docker cp test-ee.pem.key $RTA_CONTAINER:/
    $ docker cp test-ee.pem.crl $RTA_CONTAINER:/

To sign an RTA object:

    # echo "asdf" > content
    # sign-rta-external \
        --ee-cert test-ee.pem \
        --ee-key test-ee.pem.key \
        --crl test-ee.pem.crl \
        --path content \
        --resources {resources} \
        --out rta

To verify the RTA object:

    # verify-rta --ca-cert-path ./trusted.pem --path content --in rta
    Verification succeeded.

### Test UI

    $ cd ui
    $ docker build -t apnic/rpki-rta-ui .
    $ docker run -p8080:80 -it apnic/rpki-rta-ui

The UI will then be accessible at
http://localhost:8080/cgi-bin/rpki-rta.

### Todo

   - Canonicalisation of signing input.
   - More CMS validity checks.
   - Documentation/tidying of code.

### License

See [LICENSE](./LICENSE).
