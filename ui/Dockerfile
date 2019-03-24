FROM apnic/rpki-rta

RUN apt-get update -y
RUN apt-get install -y \
    apache2 \
    libcgi-pm-perl \
    vim \
    libio-capture-perl
COPY start /start
COPY favicon.ico /var/www/html/
COPY rpki-rta /usr/lib/cgi-bin/
CMD ["/start"]
