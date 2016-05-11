package main_test

import (
	"net/http/httptest"
	"testing"

	m "github.com/brimstone/go-le-proxy"
)

func Test_Proxies(*testing.T) {
	ts := httptest.NewServer(m.Mux)
}
