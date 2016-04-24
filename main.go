package main

import (
	"crypto/tls"
	"log"
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

	// check port
	port := ":" + defaultEnvString("PORT", "443", false)

	// ACME server
	// TODO finish this
	staging := defaultEnvString("STAGING", "false", false)
	acmeServer := "https://acme-v01.api.letsencrypt.org/directory"
	if staging == "true" {
		acmeServer = "https://acme-staging.api.letsencrypt.org/directory"
	}
	// TODO Setup variables for the cert and whatnot
	tlscert := defaultEnvString("TLSCERT", "", false)
	tlskey := defaultEnvString("TLSKEY", "", false)
	registration := defaultEnvString("LE_REG", "", false)
	privatekey := defaultEnvString("LE_PK", "", false)

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
		newproxy.ProxyHandler = httputil.
			NewSingleHostReverseProxy(newproxy.RemoteURL)

		proxies = append(proxies, newproxy)
	}
	log.Println(gettingCertsMsg)

	// setup Let's Encrypt
	w, err := acmewrapper.New(acmewrapper.Config{
		Domains: acmedomains,
		Address: port,

		TLSCertFile: tlscert,
		TLSKeyFile:  tlskey,

		// Let's Encrypt stuff
		RegistrationFile: registration,
		PrivateKeyFile:   privatekey,

		Server: acmeServer,

		TOSCallback: acmewrapper.TOSAgree,
	})

	if err != nil {
		panic(err)
	}

	ln, err := tls.Listen("tcp", port, w.TLSConfig())

	if err != nil {
		panic(err)
	}

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
			r.Host = proxy.RemoteURL.Host
			log.Println(logPrefix + proxy.RemoteURL.String())
			proxy.ProxyHandler.ServeHTTP(w, r)
			return
		}
		// check path
		for _, proxy := range proxies {
			pathless := strings.TrimPrefix(r.RequestURI, "/"+proxy.Path)
			if r.RequestURI == pathless {
				continue
			}
			r.URL, err = url.Parse(proxy.RemoteURL.String() + pathless)
			if err != nil {
				panic(err)
			}
			r.Host = proxy.RemoteURL.Host
			log.Println(logPrefix + proxy.RemoteURL.String() + pathless)
			proxy.ProxyHandler.ServeHTTP(w, r)
			//log.Printf("%#v\n", fakew)
			return
		}

		log.Println(logPrefix + "file://" + dirpath + r.URL.Path)
		fileserver.ServeHTTP(w, r)
	}
}
