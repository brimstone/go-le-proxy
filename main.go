package main

import (
	"crypto/tls"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"strings"

	"github.com/dkumor/acmewrapper"
)

// Proxy holds information about our different proxies
type Proxy struct {
	Path         string
	RemoteURL    *url.URL
	ProxyHandler *httputil.ReverseProxy
	Subdomain    string
}

func defaultEnvString(envvar string, d string, required bool) string {
	value := os.Getenv(envvar)
	if value == "" {
		if required {
			log.Fatalln(envvar, "must be set")
		}
	} else {
		return value
	}

	return d
}

// bulk copy from httputil source

// NewSingleHostReverseProxy returns a new ReverseProxy to a single host
func NewSingleHostReverseProxy(host string, target *url.URL) *httputil.ReverseProxy {
	targetQuery := target.RawQuery
	director := func(req *http.Request) {
		req.URL.Scheme = target.Scheme
		req.URL.Host = target.Host
		req.URL.Path = singleJoiningSlash(target.Path, req.URL.Path)
		req.Header.Set("X-Forwarded-Host", host)
		req.Header.Set("X-Target", target.String())
		if targetQuery == "" || req.URL.RawQuery == "" {
			req.URL.RawQuery = targetQuery + req.URL.RawQuery
		} else {
			req.URL.RawQuery = targetQuery + "&" + req.URL.RawQuery
		}
	}
	// We don't care about tls on the inside
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true,
			ServerName:         host,
		},
	}
	return &httputil.ReverseProxy{
		Director:  director,
		Transport: transport,
	}
}

func singleJoiningSlash(a, b string) string {
	aslash := strings.HasSuffix(a, "/")
	bslash := strings.HasPrefix(b, "/")
	switch {
	case aslash && bslash:
		return a + b[1:]
	case !aslash && !bslash:
		return a + "/" + b
	}
	return a + b
}

// end bulk copy

func setupLetsEncrypt(acmedomains []string, address string) (net.Listener, error) {

	// ACME server
	staging := defaultEnvString("STAGING", "false", false)
	acmeServer := "https://acme-v01.api.letsencrypt.org/directory"
	if staging == "true" {
		acmeServer = "https://acme-staging.api.letsencrypt.org/directory"
	}
	// Setup variables for the cert and whatnot
	tlscert := defaultEnvString("TLSCERT", "", false)
	tlskey := defaultEnvString("TLSKEY", "", false)
	registration := defaultEnvString("LE_REG", "", false)
	privatekey := defaultEnvString("LE_PK", "", false)

	// setup Let's Encrypt
	w, err := acmewrapper.New(acmewrapper.Config{
		Domains: acmedomains,
		Address: address,

		TLSCertFile: tlscert,
		TLSKeyFile:  tlskey,

		// Let's Encrypt stuff
		RegistrationFile: registration,
		PrivateKeyFile:   privatekey,

		Server: acmeServer,

		TOSCallback: acmewrapper.TOSAgree,
	})

	if err != nil {
		return nil, err
	}

	ln, err := tls.Listen("tcp", address, w.TLSConfig())

	if err != nil {
		return nil, err
	}
	return ln, nil
}

func main() {
	var err error
	// Check our variables
	// check baseDomain
	baseDomain := defaultEnvString("BASE_DOMAIN", "", true)
	// check subdomainSuffix
	subdomainSuffix := defaultEnvString("SUBDOMAIN_SUFFIX", "", false)
	if subdomainSuffix != "" {
		subdomainSuffix = subdomainSuffix + "."
	}

	// setup internal variables

	proxies := []Proxy{}

	acmedomains := []string{baseDomain}
	gettingCertsMsg := "Getting certs for: " + baseDomain
	for _, env := range os.Environ() {
		if len(env) < 6 || env[0:6] != "PROXY_" {
			continue
		}
		proxyenv := env[6:]
		proxybits := strings.Split(proxyenv, "=")

		newproxy := Proxy{}
		newproxy.Path = strings.ToLower(proxybits[0])
		newproxy.Subdomain = newproxy.Path + "." + subdomainSuffix + baseDomain

		if proxybits[1][0:1] == "!" {
			proxybits[1] = proxybits[1][1:]
		} else {
			log.Printf("Adding a handler for %s(%s) to %s\n",
				newproxy.Path,
				newproxy.Subdomain,
				proxybits[1])
			acmedomains = append(acmedomains, newproxy.Subdomain)
			gettingCertsMsg = gettingCertsMsg + ", " + newproxy.Subdomain
		}
		newproxy.RemoteURL, err = url.Parse(proxybits[1])
		if err != nil {
			panic(err)
		}

		proxies = append(proxies, newproxy)
	}
	log.Println(gettingCertsMsg)

	// check port
	port := ":" + defaultEnvString("PORT", "443", false)

	ln, err := setupLetsEncrypt(acmedomains, port)
	// let's do it

	log.Printf("Now listening on %s\n", port)

	http.HandleFunc("/", handler(proxies))
	err = http.Serve(ln, nil)
	if err != nil {
		panic(err)
	}
}

func handler(proxies []Proxy) func(http.ResponseWriter, *http.Request) {
	dirpath, err := os.Getwd()
	if err != nil {
		panic(err)
	}
	fileserver := http.FileServer(http.Dir(dirpath))
	return func(w http.ResponseWriter, r *http.Request) {

		// build up our log line
		logPrefix := r.RemoteAddr
		logPrefix += " \"" + r.Method
		logPrefix += " https://" + r.Host + r.RequestURI + "\""
		logPrefix += " \"" + r.Header.Get("User-Agent") + "\" "

		// catch our response
		//var fakew http.ResponseWriter
		// check hosts
		for _, proxy := range proxies {
			if r.Host != proxy.Subdomain {
				continue
			}
			log.Println(logPrefix + proxy.RemoteURL.String())
			NewSingleHostReverseProxy(r.Host, proxy.RemoteURL).ServeHTTP(w, r)
			return
		}
		// check path
		for _, proxy := range proxies {
			pathless := strings.TrimPrefix(r.RequestURI, "/"+proxy.Path)
			if r.RequestURI == pathless {
				continue
			}
			// TODO use singleJoiningSlash
			r.URL, err = url.Parse(proxy.RemoteURL.String() + pathless)
			if err != nil {
				panic(err)
			}
			log.Println(logPrefix + proxy.RemoteURL.String() + pathless)
			NewSingleHostReverseProxy(r.Host, proxy.RemoteURL).ServeHTTP(w, r)
			return
		}

		log.Println(logPrefix + "file://" + dirpath + r.URL.Path)
		fileserver.ServeHTTP(w, r)
	}
}
