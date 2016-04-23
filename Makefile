.PHONY:	docker

go-le-proxy: main.go
	tar c . | docker run --rm -i -e TAR=1 brimstone/golang-musl \
	-o go-le-proxy -ldflags '-linkmode external -extldflags "-static" -s -w' \
	| tar x ./go-le-proxy
	goupx go-le-proxy

docker:	go-le-proxy
	docker build -t brimstone/go-le-proxy .
