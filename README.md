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

#### RTA with multiple signatures

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
