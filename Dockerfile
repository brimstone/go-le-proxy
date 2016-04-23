FROM scratch

EXPOSE 443/tcp

ENV BASE_DOMAIN="" \
    LE_PK="" \
    LE_REG="" \
    PORT="" \
    STAGING="false" \
    SUBDOMAIN_SUFFIX="" \
    TLSCERT="/certs/cert.pem" \
    TLSKEY="/certs/key.pem"

VOLUME /certs

COPY go-le-proxy /go-le-proxy

ENTRYPOINT ["/go-le-proxy"]
