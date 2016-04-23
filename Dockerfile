FROM scratch

EXPOSE 443/tcp

VOLUME /certs

ENV BASE_DOMAIN="" \
    LE_PK="" \
    LE_REG="" \
    PORT="" \
    STAGING="false" \
    SUBDOMAIN_SUFFIX="" \
    TLSCERT="/certs/cert.pem" \
    TLSKEY="/certs/key.pem"

COPY identtrust.root.pem /etc/ssl/certs/ca-certificates.crt

COPY go-le-proxy /go-le-proxy

ENTRYPOINT ["/go-le-proxy"]
