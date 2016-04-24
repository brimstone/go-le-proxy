go-le-proxy
===========

HTTPS Proxy with support for Let's Encrypt, written in Go.



Usage:
------
Start it straight, or with docker:
```
docker run --rm -it \
	-p 443:443 \
	-e BASE_DOMAIN=example.com \
	-e PROXY_subdomain=http://10.0.0.2:8080 \
	-v $PWD/www:/www:ro \
	-w /www \
	brimstone/go-le-proxy
```

This will start a container listening on 443, ready to handle requests for 
example.com and subdomain.example.com. Requests to example.com will be served
out of /www. Requests to https://subdomain.example.com and
https://example.com/subdmain will proxy through to http://10.0.0.2:8080.


Environment variables:
----------------------

Variable        |Required|Default|Description
----------------|--------|-------|-----------
BASE_DOMAIN     |yes     |       |Base domain to use for registering
LE_PK           |no      |       |File for Let's Encrypt private key
LE_REG          |no      |       |File for Let's Encrypt registration
PORT            |no      |443    |Port to listen on. Address is assumed all
STAGING         |no      |false  |Use the Let's Encrypt staging server
SUBDOMAIN_SUFFIX|no      |       |Use to suffix your subdomains. subdomain.suffix.base_domain
TLSCERT         |no      |       |File for TLS cert. Docker default is `/certs/cert.pem`
TLSKEY          |no      |       |File for TLS key. Docker default is `/certs/key.pem`

Variables prefixed with `PROXY_` control the subdomains for the proxy. The value
should be the base URL used for the target of the proxy. If the proxy target
starts with a `!`, then that subdomain target is only made available as a
directory off the base domain and not as a subdomain. This is useful when a DNS
entry is not setup for that subdomain.
