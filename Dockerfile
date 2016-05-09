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

COPY app /app

ENTRYPOINT ["/app"]
