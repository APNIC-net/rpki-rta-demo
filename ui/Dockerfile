FROM apnic/rpki-rta

RUN apt-get update -y
RUN apt-get install -y \
    apache2 \
    libcgi-pm-perl \
    vim
COPY start /start
COPY rpki-rta /usr/lib/cgi-bin/
CMD ["/start"]
