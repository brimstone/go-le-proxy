go-le-proxy
===========

HTTPS Proxy with support for Let's Encrypt, written in Go.



Usage:
------
Start it straight, or with docker:
```
docker run --rm -it -p 443:443 -e BASE_DOMAIN=example.com \
-e PROXY_subdomain=http://10.0.0.2:8080 -v $PWD/www:/www:ro -w /www
brimstone/go-le-proxy
```

This will start a container listening on 443, ready to handle requests for 
example.com and subdomain.example.com. Requests to example.com will be served
out of /www. Requests to https://subdomain.example.com and
https://example.com/subdmain will proxy through to http://10.0.0.2:8080.
