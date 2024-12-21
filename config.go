package main

import (
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"errors"
	"log"
	"os"
	"path/filepath"
	"strings"

	"github.com/BurntSushi/toml"
)

type DomainInfo struct {
	Domain         string
	Target         string
	WidgetBotName  string
	WidgetBotToken string
	UserSuffix     string
	Whitelist      []string
	LoginFrom      string
	NoAuth         bool
	TelegramUsers  map[string]string
	AuthorizedKeys string
}

type Config struct {
	SSH struct {
		Enabled        bool
		Port           string
		ServerKey      string
		AuthorizedKeys string
	}
	Certificate struct {
		Type  string
		Email string
		Cert  string
		Key   string
	}
	FilterSpam       bool
	Gzip             bool
	DropPrivileges   bool
	Listen           string
	HttpsPort        string
	DefaultTarget    string
	RedirectHTTP     bool
	MaxNonActiveTime int
	CustomPage       string
	LogoutURL        string
	SSO              string
	// TelegramBotName  string
	// TelegramBotToken string
	TelegramUsers map[string]string
	Domains       []DomainInfo
}

type SSH_Info struct {
	keyType  string
	keyData  []byte
	username string
}

func loadConfig() {
	// Config filename can be provided via command line
	config_file := "jauth.toml"
	if len(os.Args) > 1 {
		config_file = os.Args[1]
		// Change current dir to dir of config file
		err := os.Chdir(filepath.Dir(config_file))
		if err != nil {
			log.Fatal(err)
		}
	}
	// Some default settings
	cfg.SSH.Enabled = true
	cfg.SSH.Port = "2222"
	cfg.SSH.ServerKey = "~/.ssh/id_rsa"
	cfg.SSH.AuthorizedKeys = "~/.ssh/authorized_keys"
	cfg.Certificate.Type = "self-signed"
	cfg.DefaultTarget = "8080"
	cfg.FilterSpam = true      // Less spam like `http: TLS handshake error...`
	cfg.Gzip = true            // Enable gzip'ing the responses
	cfg.DropPrivileges = false // Drop privileges if started from root
	cfg.Listen = "0.0.0.0"     // Interface to listen
	cfg.HttpsPort = "443"
	cfg.RedirectHTTP = true   // Start server on 80 port that will redirect all to 443 port
	cfg.MaxNonActiveTime = 30 // TOKEN_COUNTDOWN_TIMER
	cfg.LogoutURL = "/jauth-logout"

	// Load user's config file
	// Toml module will automatically parse file into struct
	_, err := toml.DecodeFile(config_file, &cfg)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			log.Print(red("Configuration file not found"))
		} else {
			log.Fatal(err)
		}
	}
	// Support paths with tilde ~
	cfg.SSH.ServerKey = expandTilde(cfg.SSH.ServerKey)
	cfg.SSH.AuthorizedKeys = expandTilde(cfg.SSH.AuthorizedKeys)
	cfg.Certificate.Cert = expandTilde(cfg.Certificate.Cert)
	cfg.Certificate.Key = expandTilde(cfg.Certificate.Key)
	// Load default authorized_keys
	if cfg.SSH.Enabled && cfg.SSH.AuthorizedKeys != "" {
		defaultWhitelist = loadAuthorizedKeys(cfg.SSH.AuthorizedKeys)
	}
	defaultWhitelist = append(defaultWhitelist, handleTelegramUsers(cfg.TelegramUsers)...)
	defaultWhitelist = removeDuplicates(defaultWhitelist)
	log.Printf("Default WhiteList: %s", strings.Join(defaultWhitelist, ", "))

	// Load login page. There is a built-in and the user can provide his own
	raw_index_page := []byte(embed_index_html)
	if cfg.CustomPage != "" {
		raw_index_page, err = os.ReadFile(cfg.CustomPage)
		if err != nil {
			log.Fatal(err)
		}
		log.Print("Using custom login page: ", cfg.CustomPage)
	}

	// Add Domain_Info for non specified domains, ip address
	cfg.Domains = append(cfg.Domains, DomainInfo{})
	// Domain processing
	for i, domain := range cfg.Domains {
		// In case the user has not specified a target
		// Also for Domain_Info declared just above
		if domain.Target == "" {
			domain.Target = cfg.DefaultTarget
		}
		// "Register" per domain TelegramUsers and SshKeys
		newUsers := handleTelegramUsers(domain.TelegramUsers)
		if domain.AuthorizedKeys != "" {
			newUsers = append(newUsers, loadAuthorizedKeys(expandTilde(domain.AuthorizedKeys))...)
		}
		// Fill empty whitelist with default and per domain values
		if len(domain.Whitelist) == 0 {
			domain.Whitelist = newUsers
			domain.Whitelist = append(domain.Whitelist, defaultWhitelist...)
		}
		// Each domain can be configured to sign in through a different domain
		// Otherwise use Single Sign-On url
		if (domain.LoginFrom == "") && (domain.Domain != cfg.SSO) {
			domain.LoginFrom = cfg.SSO
		}
		// Calc key for HMAC. Need for verification telegram widget auth
		if domain.WidgetBotToken != "" {
			tmp_sha256 := sha256.New()
			tmp_sha256.Write([]byte(domain.WidgetBotToken))
			domainToTokenSHA256[domain.Domain] = tmp_sha256.Sum(nil)
		}
		// We need to know if there is at least one widget, otherwise we turn off its support
		current_widget_enabled := domain.WidgetBotName != ""
		if current_widget_enabled {
			telegramWidgetEnabled = true
		}
		// CSS for hiding blocks
		widget_block_css := "display: none;"
		if current_widget_enabled {
			widget_block_css = ""
		}
		ssh_block_css := "display: none;"
		if cfg.SSH.Enabled {
			ssh_block_css = ""
		}
		// Fill template for each domain
		login_page := string(raw_index_page)
		login_page = strings.Replace(login_page, "{WIDGET_DISABLING_CSS}", widget_block_css, -1)
		login_page = strings.Replace(login_page, "{TELEGRAM_BOT_NAME}", domain.WidgetBotName, -1)
		login_page = strings.Replace(login_page, "{SSH_DISABLING_CSS}", ssh_block_css, -1)
		login_page = strings.Replace(login_page, "{SSH_PORT}", cfg.SSH.Port, -1)
		login_page = strings.Replace(login_page, "{DOMAIN}", domain.Domain, -1)
		// GZip page
		var buf bytes.Buffer
		zw, _ := gzip.NewWriterLevel(&buf, gzip.BestCompression)
		_, err = zw.Write([]byte(login_page))
		if err != nil {
			log.Fatal(err)
		}
		if err := zw.Close(); err != nil {
			log.Fatal(err)
		}
		domainToLoginPage[domain.Domain] = buf.Bytes()
		domainNoAuth[domain.Domain] = domain.NoAuth
		// For easy lookup without loops
		domains[domain.Domain] = domain
		cfg.Domains[i] = domain
	}
}
