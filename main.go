package main

// Thanks to
// https://lukevers.com/2016/05/01/ssh-as-authentication-for-web-applications
// https://github.com/suyashkumar/ssl-proxy

import (
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"embed"
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/BurntSushi/toml"
)

type Domain_Info struct {
	Domain         string
	Target         string
	WidgetBotName  string
	WidgetBotToken string
	UserSuffix     string
	Whitelist      []string
	LoginFrom      string
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
		Email string // TODO
		Cert  string
		Key   string
	}
	DropPrivileges   bool
	Listen           string // Interface to listen
	DefaultTarget    string
	RedirectHTTP     bool
	MaxNonActiveTime int
	CustomPage       string
	LogoutURL        string
	SSO              string
	// TelegramBotName  string
	// TelegramBotToken string
	TelegramUsers map[string]string
	Domains       []Domain_Info
}

var cfg Config

type SSH_Info struct {
	keyType string
	keyData []byte
	session []byte
}

var (
	telegramWidgetEnabled = false
	authorized_keys       = map[string]SSH_Info{}
	domainToTokenSHA256   = map[string][]byte{}
	domainToLoginPage     = map[string][]byte{} // gzip
	domains               = map[string]Domain_Info{}
)

// Next comment will embed `index.html` file into executable during compile time
//
//go:embed index.html
var embed_index_html embed.FS

//go:embed NotInWhitelist.html
var NotInWhitelist_PAGE string

func main() {
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
	cfg.DropPrivileges = false // Drop privileges if started from root
	cfg.Listen = "0.0.0.0"
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
	// Replace empty telegram usernames
	for telegram_name, our_name := range cfg.TelegramUsers {
		if our_name == "" {
			our_name, _ = strings.CutPrefix(telegram_name, "@")
			cfg.TelegramUsers[telegram_name] = our_name
		}
	}

	// Load authorized_keys
	if cfg.SSH.Enabled {
		loadAuthorizedKeys(cfg.SSH.AuthorizedKeys)
		if len(authorized_keys) == 0 {
			log.Printf("Zero authorized keys. SSH server will no start")
			cfg.SSH.Enabled = false
		}
	}

	// Load login page. There is a built-in and the user can provide his own
	var raw_index_page []byte
	if cfg.CustomPage != "" {
		raw_index_page, err = os.ReadFile(cfg.CustomPage)
		log.Print("Using custom login page: ", cfg.CustomPage)
	} else {
		raw_index_page, err = embed_index_html.ReadFile("index.html")
	}
	if err != nil {
		log.Fatal(err)
	}

	// Add Domain_Info for non specified domains, ip address
	cfg.Domains = append(cfg.Domains, Domain_Info{})
	// Domain processing
	for i, domain := range cfg.Domains {
		// In case the user has not specified a target
		// Also for Domain_Info declared just above
		if domain.Target == "" {
			domain.Target = cfg.DefaultTarget
			cfg.Domains[i] = domain
		}
		// Each domain can be configured to sign in through a different domain
		// Otherwise use Single Sign-On url
		if (domain.LoginFrom == "") && (domain.Domain != cfg.SSO) {
			domain.LoginFrom = cfg.SSO
			cfg.Domains[i] = domain
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
		// For easy lookup without loops
		domains[domain.Domain] = domain
	}

	// Load tokens for authorized users
	loadTokens()
	// Some info for admin
	log.Printf("Users registered: %d", len(authorized_keys)+len(cfg.TelegramUsers))
	log.Printf("Active tokens: %d", len_tokens())

	if (len(authorized_keys) == 0) && (len(cfg.TelegramUsers) == 0) {
		log.Print(red("Neither Telegram users nor SSH are provided. NO ONE CAN LOGIN!"))
	}

	// Drop privileges if allowed and started from root
	if (syscall.Getuid() == 0) && (cfg.DropPrivileges == true) {
		err := dropPrivileges()
		if err != nil {
			log.Fatal("Cant drop root privileges!\n", err)
		}
		fmt.Println("Dropping privileges. Program will not be able to save the session tokens!")
	}

	handleCerts()
	go startWebServer()
	if cfg.SSH.Enabled {
		go startSshServer()
	}
	go tokensCountdown()
	select {}
}

// Add proper ANSI escape codes to render it green-colored in a supported terminal
func green(in string) string {
	return fmt.Sprintf("\033[0;32m%s\033[0;0m", in)
}

func red(in string) string {
	return fmt.Sprintf("\033[0;31m%s\033[0;0m", in)
}

func expandTilde(path string) string {
	// Expand tilde ~ to home dir
	user_dir, err := os.UserHomeDir()
	if err != nil {
		log.Fatal(err)
	}
	if strings.HasPrefix(path, "~/") {
		return filepath.Join(user_dir, path[2:])
	}
	return path
}
