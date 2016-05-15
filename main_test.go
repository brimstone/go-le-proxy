package main_test

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	m "github.com/brimstone/go-le-proxy"
)

func Test_NewProxyHandler(t *testing.T) {

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintln(w, "Hello, client")
		fmt.Println(r.Host)
		fmt.Println(r.RequestURI)
	}))
	defer ts.Close()

	url, _ := url.Parse(ts.URL)
	proxyFunc := m.NewSingleHostReverseProxy("asdf", url)
	if r, err := http.NewRequest("GET", "/asdf", nil); err != nil {
		t.Errorf("%v", err)
	} else {
		r.Host = "asdf"
		recorder := httptest.NewRecorder()
		proxyFunc.ServeHTTP(recorder, r)
		if recorder.Code != http.StatusOK {
			t.Errorf("returned %v. Expected %v.", recorder.Code, http.StatusOK)
		}
	}
}
