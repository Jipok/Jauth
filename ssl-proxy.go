package main

import (
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/suyashkumar/ssl-proxy/gen"
	"golang.org/x/crypto/acme/autocert"
)

const (
	SELF_SIGNED_CERT_FILE = "self-signed.crt"
	SELF_SIGNED_KEY_FILE  = "self-signed.key"
	AUTOCERT_DIR_CACHE    = "jauth-autocert"
)

func handleCerts() {
	if (cfg.Certificate.Cert != "") && (cfg.Certificate.Type != "manual") {
		log.Print("Certificate.Cert and Certificate.Key are ignored since not a manual mode")
	}

	switch cfg.Certificate.Type {
	case "autocert":
		log.Printf("Using LetsEncrypt to autogenerate and serve certs for all domains")
	case "manual":
		_, err := os.Stat(cfg.Certificate.Cert)
		if err != nil {
			log.Fatalf("Problem wit Certificate.Cert file: %s", err)
		}
		_, err = os.Stat(cfg.Certificate.Key)
		if err != nil {
			log.Fatalf("Problem wit Certificate.Key file: %s", err)
		}
		log.Printf("Using provided Cert and Key for all domains")
	case "self-signed":
		cfg.Certificate.Cert = SELF_SIGNED_CERT_FILE
		cfg.Certificate.Key = SELF_SIGNED_KEY_FILE
		// Checking for a previously generated certificate
		_, err := os.Stat(cfg.Certificate.Cert)
		if err == nil {
			log.Printf("Using the previously generated self-signed certificate")
			break
		}
		// Generate new self-signed tls cert via original ssl-proxy library
		log.Print("Generating a new self-signed certificate")
		certBuf, keyBuf, fingerprint, err := gen.Keys(365 * 24 * time.Hour)
		if err != nil {
			log.Fatal("Error generating default keys", err)
		}
		// Save Cert
		certOut, err := os.Create(cfg.Certificate.Cert)
		if err != nil {
			log.Fatalf("Unable to create %s file: %s", SELF_SIGNED_CERT_FILE, err)
		}
		certOut.Write(certBuf.Bytes())
		// Save Key
		keyOut, err := os.OpenFile(SELF_SIGNED_KEY_FILE, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
		if err != nil {
			log.Fatalf("Unable to create %s file: %s", SELF_SIGNED_KEY_FILE, err)
		}
		keyOut.Write(keyBuf.Bytes())

		log.Printf("SHA256 Fingerprint: % X", fingerprint)
	default:
		log.Printf("Wrong value for Certificate.Type: %s", cfg.Certificate.Type)
		log.Fatalf("Must be one of: autocert, self-signed, manual")
	}
}

// Convert string with port or address:port ot URL type
func targetToURL(target string) (*url.URL, error) {
	// Allow to specify only port
	if !strings.Contains(target, ":") {
		target = "http://127.0.0.1:" + target
	}
	// Ensure the to URL start from http://
	if !strings.HasPrefix(target, "http://") && !strings.HasPrefix(target, "https://") {
		target = "http://" + target
	}
	// Parse as a URL
	return url.Parse(target)
}

func startWebServer() {
	// Parse target of user's domains
	toURLs := map[string]*url.URL{}
	var domains []string
	for _, d := range cfg.Domains {
		toURL, err := targetToURL(d.Target)
		if err != nil {
			log.Fatalf("Unable to parse target url `%s` for domain `%s`: %s", d.Target, d.Domain, err)
		}
		toURLs[d.Domain] = toURL
		// Domain_Info used for DefaultTarget(non specified domains, ip address)
		if d.Domain == "" {
			// With autocert we using HostWhitelist
			// Hiding the default target since it can't be used in that case
			if cfg.Certificate.Type != "autocert" {
				log.Print(green("Default target for unspecified domains: "), toURL)
			}
			continue
		} else {
			domains = append(domains, d.Domain)
		}
		log.Printf(green("Proxying from https://%s to %s"), d.Domain, toURL)
	}
	if cfg.Certificate.Type == "autocert" {
		log.Print("With autocert using HostWhitelist: ", strings.Join(domains, ", "))
	}

	// Setup reverse proxy
	proxy := &httputil.ReverseProxy{
		Rewrite: func(r *httputil.ProxyRequest) {
			// Use default target(with empty domain) for everything we don't know how to redirect
			target := toURLs[r.In.Host]
			if target == nil {
				target = toURLs[""]
			}
			// Based on doc for SetURL
			r.SetURL(target)
			r.SetXForwarded()
			r.Out.Host = r.In.Host
		},
	}
	// See auth-handler.go
	mux := newAuthMux(proxy)

	// Listen http on 80 port and redirect all incoming to https
	if cfg.RedirectHTTP {
		log.Println("Redirecting http(:80) requests to https(:443)")
		redirectTLS := func(w http.ResponseWriter, r *http.Request) {
			http.Redirect(w, r, "https://"+r.Host+r.RequestURI, http.StatusMovedPermanently)
		}
		go func() {
			err := http.ListenAndServe(cfg.Listen+":80", http.HandlerFunc(redirectTLS))
			if err != nil {
				log.Fatal("HTTP redirection server failure", err)
			}
		}()
	}

	address := cfg.Listen + ":443"
	log.Printf("Web server is listening: %s", address)
	if cfg.Certificate.Type == "autocert" {
		// For some reason LetsEncrypt seems to only work on :443
		m := &autocert.Manager{
			Cache:      autocert.DirCache(AUTOCERT_DIR_CACHE),
			Prompt:     autocert.AcceptTOS,
			HostPolicy: autocert.HostWhitelist(domains...),
		}
		s := &http.Server{
			Addr:      address,
			TLSConfig: m.TLSConfig(),
			Handler:   mux,
		}
		log.Fatal(s.ListenAndServeTLS("", ""))
	} else {
		// manual or self-signed mode. Serve TLS using provided/generated certificate files
		log.Fatal(http.ListenAndServeTLS(address, cfg.Certificate.Cert, cfg.Certificate.Key, mux))
	}

}
