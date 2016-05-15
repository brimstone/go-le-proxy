include ${PROJECTBUILDER}/Makefile

test:
	STAGING=true \
	PORT=8443 \
	TLSCERT=staging.crt \
	TLSKEY=staging.key \
	PROXY_base=https://127.0.0.1:8000/ \
	./app

