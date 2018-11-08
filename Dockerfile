FROM ubuntu:16.04

RUN apt-get update -y
RUN apt-get install -y \
    libhttp-daemon-perl \
    liblist-moreutils-perl \
    libwww-perl \
    libcarp-always-perl \
    libconvert-asn1-perl \
    libclass-accessor-perl \
    cpanminus \
    libssl-dev \
    libyaml-perl \
    libxml-libxml-perl \
    libio-capture-perl \
    libnet-ip-perl \
    make \
    wget \
    patch \
    gcc
COPY cms.diff .
RUN wget https://ftp.openssl.org/source/openssl-1.0.2p.tar.gz \
    && tar xf openssl-1.0.2p.tar.gz \
    && cd openssl-1.0.2p \
    && patch -p0 < /cms.diff \
    && ./config enable-rfc3779 \
    && make \
    && make install
RUN cpanm Set::IntSpan Net::CIDR::Set
COPY . /root/rpki-rta
RUN cd /root/rpki-rta/ && perl Makefile.PL && make && make test && make install
RUN rm -rf /root/rpki-rta/
ENTRYPOINT /bin/bash
