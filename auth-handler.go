package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"
	"time"
)

const (
	// These are the boundaries for a valid response from a telegram login widget
	// I usually have a length of 215 characters
	TELEGRAM_MIN_REQUEST_LENGTH = 100
	TELEGRAM_MAX_REQUEST_LENGTH = 350
)

// Auth router
func newAuthMux(handler http.Handler) *http.ServeMux {
	mux := http.NewServeMux()
	if telegramWidgetEnabled && (len(cfg.TelegramUsers) != 0) {
		mux.HandleFunc("/jauth-telegram", handleTelegramAuth)
	}
	mux.HandleFunc(cfg.LogoutURL, handleLogout)
	mux.HandleFunc("/jauth-check", handleCheckAuth)
	// This is necessary to make a closure and forward the reverse proxy to the handler function
	auth := buildAuthHandler(handler)
	mux.Handle("/", auth)
	return mux
}

// Func that responds to the client with our gziped login page
func writeIndexPage(w http.ResponseWriter, req *http.Request) {
	// We ignore "Content-Encoding" from client
	// Today there are no browsers without gzip compression support
	// And this saves us from implementing a bunch of logic
	w.Header().Add("Content-Encoding", "gzip")
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	// Unfortunately, there are (at the time of 2023) browsers that do not show
	// the content of the page if they receive a 407 error
	// w.WriteHeader(http.StatusProxyAuthRequired)
	page := domainToLoginPage[req.Host]
	// Following is needed for unspecified domains in `manual` and `self-signed` modes
	// It will also be used if client requested without a domain(by ip address)
	if page == nil {
		page = domainToLoginPage[""]
	}
	w.Header().Add("WWW-Authenticate", "Bearer realm=\"JAuth\"")
	w.WriteHeader(http.StatusUnauthorized)
	w.Write(page)
}

// Handler of cfg.LogoutURL
func handleLogout(w http.ResponseWriter, req *http.Request) {
	cookie, err := req.Cookie("jauth_token")
	if err == nil {
		tmp, in_tokens := tokens.Load(cookie.Value)
		if in_tokens {
			tokenInfo := tmp.(Token_Info)
			log.Printf("User `%s` logged out. Token: %s", tokenInfo.username, cookie.Value)
			tokens.Delete(cookie.Value)
		}
	}
	// MaxAge: -1 mean deleting cookie
	http.SetCookie(w, &http.Cookie{Name: "jauth_token", Value: "", MaxAge: -1})
	http.Redirect(w, req, "https://"+req.Host, http.StatusFound)
}

// Single Sign-On. Third step
func SSO3(w http.ResponseWriter, req *http.Request) bool {
	tokenPlusURI, found := strings.CutPrefix(req.RequestURI, "/jauth-sso-token/")
	// Not an SSO request, go back and continue
	if !found {
		return false
	}
	// Now the user is successfully authorized on LoginFrom and returned back
	// Well this is assumed under normal use. In fact, anyone can call this endpoint
	// But now we are not interested in the truth. We simply set the specified
	// token as cookie and redirect to the requested address. This should be safe
	// for us on any data received.
	parts := strings.SplitN(tokenPlusURI, "/", 2)
	url := "https://" + req.Host + "/"

	// This should always be the case in normal use.
	// But since this is a public endpoint, anything can happen.
	if len(parts) == 2 {
		url += parts[1]
	}
	// We give the user an authorization token from another domain
	// TODO no 3th redirect
	http.SetCookie(w, &http.Cookie{Name: "jauth_token", Value: parts[0], HttpOnly: true, SameSite: http.SameSiteStrictMode, Path: "/"})
	// Redirect to the user's original page
	http.Redirect(w, req, url, http.StatusFound)
	return true
}

// Single Sign-On. Second step
func SSO2(w http.ResponseWriter, req *http.Request, token string, username string) bool {
	domainPlusURI, found := strings.CutPrefix(req.RequestURI, "/jauth-sso/")
	// Not an SSO request, go back and continue
	if !found {
		return false
	}
	// Here we know that the user is authorized and he came to us from another
	// domain. The only thing that is not trustworthy is the current URI.
	// A inattentive user can follow an attacker's link, so we make sure that
	// domain to which the user needs to be returned is processed by us.
	target := "https://"
	parts := strings.SplitN(domainPlusURI, "/", 2)
	if len(parts) == 2 {
		targetDomain := parts[0]
		// Check target domain
		_, ok := domains[targetDomain]
		if !ok {
			log.Printf(red("Warning! User `%s` tried to transfer an authorization token to a foreign domain: %s"), username, targetDomain)
			target += req.Host
		} else {
			target += targetDomain
			target += "/jauth-sso-token/"
			target += token
			target += "/"
			target += parts[1]
			log.Printf("User `%s` logged in to `%s` through `%s`. Token: %s", username, targetDomain, req.Host, token)
		}
	} else {
		// Something went wrong. Leave the user on the current domain
		target += req.Host
	}
	http.Redirect(w, req, target, http.StatusFound)
	return true
}

// Single Sign-On. First step
func SSO1(w http.ResponseWriter, req *http.Request) bool {
	// Not an SSO request, go back and continue
	if domains[req.Host].LoginFrom == "" {
		return false
	}
	// Just redirect to the configured login domain. We also pass the current
	// URI to return the user to it after authorization. We don't encode the
	// current URI in any way because it's already a valid URI and from the
	// browser's point of view we just changed the path at the beginning.
	target := "https://" + domains[req.Host].LoginFrom + "/jauth-sso/"
	target += req.Host
	// URI can be just one `/`. And this is only option of invalid URI for us.
	// We do not add it as we will get `//` at the end which will force the
	// browser to make an additional useless request
	// if len(req.RequestURI) > 1 {
	target += req.RequestURI
	// }
	http.Redirect(w, req, target, http.StatusFound)
	return true
}

// Called by JS every second to check if the token is authorized
func handleCheckAuth(w http.ResponseWriter, req *http.Request) {
	// Check for ssh token
	if len(ssh_tokens) > 0 {
		cookie, err := req.Cookie("jauth_ssh_token")
		if (err == nil) && (len(cookie.Value) > 0) {
			sshToken := cookie.Value
			// Lock and read global var
			ssh_tokens_mutex.RLock()
			ssh_token_info, in_tokens := ssh_tokens[sshToken]
			ssh_tokens_mutex.RUnlock()
			if in_tokens {
				// SSH token match. User authorized
				token := provideCookieWithNewToken(w, req, ssh_token_info.username)
				// Force JS script to refresh the page
				w.Write([]byte("true"))
				// Provide browser information to ssh
				addr := strings.SplitN(req.RemoteAddr, ":", 2)
				ssh_token_info.browserAddr = addr[0] // Drop useless client's port
				ssh_token_info.browserAgent = req.UserAgent()
				// Thanks to SSO3, it's very easy to implement ability to share a link to a session.
				// JS side gives us either the current host or the host to be redirected to after SSO2.
				ssh_token_info.browserLink = "https://" + req.URL.RawQuery + "/jauth-sso-token/" + token + "/"
				// Lock and modify global var
				ssh_tokens_mutex.Lock()
				ssh_tokens[sshToken] = ssh_token_info
				ssh_tokens_mutex.Unlock()
				return
			}
		}
	}
	// User could have logged into site through a different browser tab. Check it
	cookie, err := req.Cookie("jauth_token")
	if err == nil {
		token := cookie.Value
		_, in_tokens := tokens.Load(token)
		if in_tokens {
			// Force JS script to refresh the page
			w.Write([]byte("true"))
		}
	}
}

// Main auth handler function.
func buildAuthHandler(handler http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		// Single Sign-On. Third step
		if SSO3(w, req) {
			return
		}
		// Check token
		cookie, err := req.Cookie("jauth_token")
		if err == nil {
			token := cookie.Value
			// Check token
			tmp, in_tokens := tokens.Load(token)
			if in_tokens {
				tokenInfo := tmp.(Token_Info)
				username := tokenInfo.username
				// Single Sign-On. Second step
				if SSO2(w, req, token, username) {
					return
				}
				// Check token countdown
				if tokenInfo.countdown < cfg.MaxNonActiveTime {
					// Not save instantly, since tokensCountdown will save soon anyway
					tokenInfo.countdown = cfg.MaxNonActiveTime
					tokens.Store(token, tokenInfo)
				}
				// Check useragent and IP address change
				ip := strings.Split(req.RemoteAddr, ":")[0]
				lastEntry := tokenInfo.history[len(tokenInfo.history)-1]
				if (lastEntry.ip != ip) || (lastEntry.useragent != req.UserAgent()) {
					tokenInfo.history = append(tokenInfo.history, Token_Usage_History{
						time:      time.Now().Unix(),
						ip:        ip,
						useragent: req.UserAgent(),
					})
					tokens.Store(token, tokenInfo)
					// Important information, save now
					go saveTokens()
				}
				// Check for domain whitelist. Empty array mean all allowed
				whitelist := domains[req.Host].Whitelist
				if len(whitelist) > 0 {
					found := false
					for _, in_list := range whitelist {
						if username == in_list {
							found = true
							break
						}
					}
					if !found {
						w.WriteHeader(http.StatusForbidden)
						fmt.Fprintf(w, NotInWhitelist_PAGE, username, cfg.LogoutURL)
						return
					}
				}
				// Add suffix if present
				username = username + domains[req.Host].UserSuffix
				// Set proper header
				req.Header.Set("Remote-User", username)
				req.Header.Set("X-Forwarded-User", username)
				// Passing the modified request to the reverse proxy
				handler.ServeHTTP(w, req)
				return
			}
		}
		// Does the site need our authorization?
		if domainNoAuth[req.Host] {
			// Preventing deception
			req.Header.Del("Remote-User")
			req.Header.Del("X-Forwarded-User")
			handler.ServeHTTP(w, req)
			return
		}
		// Single Sign-On. First step
		if SSO1(w, req) {
			return
		}

		writeIndexPage(w, req)
	})
}

// Checks if the user has successfully logged in with Telegram.
func handleTelegramAuth(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "", http.StatusMethodNotAllowed)
		return
	}

	// We do not parse obviously incorrect requests
	if (r.ContentLength < TELEGRAM_MIN_REQUEST_LENGTH) || (r.ContentLength > TELEGRAM_MAX_REQUEST_LENGTH) {
		http.Error(w, "", http.StatusRequestEntityTooLarge)
		return
	}

	telegramTokenSHA256, ok := domainToTokenSHA256[r.Host]
	if !ok {
		http.Error(w, "Telegram Widget for that domain not configured", http.StatusNotFound)
		return
	}

	// Read body of POST
	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "Error reading request body", http.StatusInternalServerError)
		return
	}

	// JS side should sent hash + \n + dataCheckString
	parts := strings.SplitN(string(body), "\n", 2)
	if len(parts) != 2 {
		http.Error(w, "Invalid data check string", http.StatusBadRequest)
		return
	}
	hash := parts[0]
	dataCheckString := parts[1]

	// https://core.telegram.org/widgets/login#checking-authorization
	hm := hmac.New(sha256.New, telegramTokenSHA256)
	hm.Write([]byte(dataCheckString))
	expectedHash := hex.EncodeToString(hm.Sum(nil))

	if expectedHash != hash {
		http.Error(w, "Hash mismatch", http.StatusBadRequest)
		return
	}

	// Split into usable map
	user := make(map[string]string)
	for _, s := range strings.Split(dataCheckString, "\n") {
		parts := strings.Split(s, "=")
		user[parts[0]] = parts[1]
	}

	// Checking whitelist
	username := cfg.TelegramUsers[user["id"]]
	if (username == "") && (user["username"] != "") {
		// I use @ for security reasons. Otherwise, any user can set their own
		// username to the specified in config ID and log in.
		username = cfg.TelegramUsers["@"+user["username"]]
	}
	if username == "" {
		log.Printf("The user tried to log in via telegram:\n%s\n\n", dataCheckString)
		resp := fmt.Sprintf("<h1 style=\"text-align:center;\">Access denied!<br>Your ID: %s</h1>", user["id"])
		http.Error(w, resp, http.StatusForbidden)
		return
	}

	// Finally
	provideCookieWithNewToken(w, r, username)
	// JS script will reload page
	w.Write([]byte("true"))

	// What TODO with provided auth_date?
	// timestamp, err := strconv.ParseInt(user["auth_date"], 10, 64)
	// if err != nil {
	// }
}

// Called upon successful authorization(telegram or ssh)
func provideCookieWithNewToken(w http.ResponseWriter, req *http.Request, username string) string {
	_, err := req.Cookie("jauth_terminate_all_other_sessions")
	if err == nil {
		fullLogOut(username)
	}
	// New token
	ip := strings.Split(req.RemoteAddr, ":")[0]
	token := newToken(username, ip, req.UserAgent())
	http.SetCookie(w,
		&http.Cookie{
			Name:     "jauth_token",
			Value:    token,
			HttpOnly: true,
			Secure:   true,
			SameSite: http.SameSiteStrictMode,
			Path:     "/",
		})
	// MaxAge: -1 mean deleting cookie
	http.SetCookie(w, &http.Cookie{Name: "jauth_ssh_token", Value: "", MaxAge: -1})
	http.SetCookie(w, &http.Cookie{Name: "jauth_terminate_all_other_sessions", Value: "", MaxAge: -1})
	return token
}
