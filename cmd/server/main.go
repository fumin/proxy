// Command proxy serves as a user facing reverse proxies for backend servers.
// Edit the configuration variables in mainWithErr to customize.
package main

import (
	"flag"
	"fmt"
	"html"
	"log"
	"net/http"
	"net/http/httputil"

	"github.com/NYTimes/gziphandler"
	"golang.org/x/crypto/acme/autocert"
)

func mainWithErr() error {
	// Configuration variables.
	//
	// email, cache, and policy configure autocert.Manager.
	email := "my@email.com"
	var cache autocert.Cache = autocert.DirCache("/var/cert")
	var policy autocert.HostPolicy = autocert.HostWhitelist(
		"my.domain",
		"www.my.domain",
		"xyz.my.domain",
	)

	// redirects specify the redirect mappings.
	redirects := map[string]string{
		"my.domain": "www.my.domain",
	}

	// backends specify the reverse proxy backends.
	backends := map[string]string{
		"www.my.domain": "localhost:12345",
		"xyz.my.domain": "localhost:22345",
	}

	certMng := &autocert.Manager{
		HostPolicy: policy,
		Email:      email,
		Cache:      cache,
		Prompt:     autocert.AcceptTOS,
	}
	// Start proxy.
	go func() {
		if err := serveTLS(certMng, redirects, backends); err != nil {
			log.Fatalf("%+v", err)
		}
	}()
	// Redirect HTTP to TLS.
	go func() {
		if err := serveToTLS(); err != nil {
			log.Fatalf("%+v", err)
		}
	}()

	log.Printf("proxy running")
	select {}
}

// responseWriter is similar to http.ResponseWriter, except that it saves the status code.
type responseWriter struct {
	status int
	http.ResponseWriter
}

func (w *responseWriter) WriteHeader(status int) {
	w.status = status
	w.ResponseWriter.WriteHeader(status)
}

// reverseProxy is an HTTP handler.
type reverseProxy struct {
	redirects map[string]string
	backends  map[string]string
	proxy     *httputil.ReverseProxy
}

func newReverseProxy(redirects, backends map[string]string) *reverseProxy {
	director := func(r *http.Request) {
		r.URL.Scheme = "http"
		r.URL.Host = backends[r.Host]
	}

	rp := &reverseProxy{
		redirects: redirects,
		backends:  backends,
		proxy:     &httputil.ReverseProxy{Director: director},
	}
	return rp
}

func (rp *reverseProxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// Redirect.
	if ok := redirectByHost(rp.redirects, w, r); ok {
		return
	}

	// Proxy.
	host := r.Host
	if _, ok := rp.backends[host]; ok {
		respW := &responseWriter{ResponseWriter: w}
		rp.proxy.ServeHTTP(respW, r)

		urlStr := fmt.Sprintf("%s%s?%s", r.Host, r.URL.EscapedPath(), r.URL.RawQuery)
		if respW.status != 200 {
			log.Printf("%s %s %d", r.Method, urlStr, respW.status)
		}
		return
	}

	// Unknown host.
	w.Write([]byte(fmt.Sprintf("unknown host: %s", host)))
}

func serveTLS(certMng *autocert.Manager, redirects, backends map[string]string) error {
	handler := newReverseProxy(redirects, backends)
	withGz := gziphandler.GzipHandler(handler)
	server := &http.Server{
		Addr:    ":443",
		Handler: withGz,
	}
	return server.Serve(certMng.Listener())
}

func serveToTLS() error {
	handler := func(w http.ResponseWriter, r *http.Request) {
		r.URL.Scheme = "https"
		r.URL.Host = r.Host
		urlStr := r.URL.String()
		http.Redirect(w, r, urlStr, http.StatusFound)
	}
	server := &http.Server{
		Addr:    ":80",
		Handler: http.HandlerFunc(handler),
	}
	return server.ListenAndServe()
}

func main() {
	flag.Parse()
	log.SetFlags(log.LstdFlags | log.Lmicroseconds | log.Llongfile)

	if err := mainWithErr(); err != nil {
		log.Fatalf("%+v", err)
	}
}

func redirectByHost(hostMap map[string]string, w http.ResponseWriter, r *http.Request) bool {
	newHost, ok := hostMap[r.Host]
	if !ok {
		return false
	}

	r.URL.Host = newHost
	urlStr := r.URL.String()
	w.Header().Set("Location", urlStr)

	code := http.StatusFound
	w.WriteHeader(code)

	// RFC 2616 recommends that a short note "SHOULD" be included in the
	// response because older user agents may not understand 301/307.
	// Shouldn't send the response for POST or HEAD; that leaves GET.
	if r.Method == "GET" {
		note := "<a href=\"" + html.EscapeString(urlStr) + "\">" + http.StatusText(code) + "</a>.\n"
		fmt.Fprintln(w, note)
	}
	return true
}
