package main

// Thanks to
// https://lukevers.com/2016/05/01/ssh-as-authentication-for-web-applications
// https://github.com/suyashkumar/ssl-proxy

import (
	_ "embed"
	"fmt"
	"log"
	"sync"
	"syscall"
)

// All globals variables here
var (
	telegramWidgetEnabled = false
	defaultWhitelist      []string
	authorized_keys       = []SSH_Info{}
	domainToTokenSHA256   = map[string][]byte{}
	domainToLoginPage     = map[string][]byte{} // gzip
	domainNoAuth          = map[string]bool{}
	domains               = map[string]DomainInfo{}
	cfg                   Config
	// Tokens that the browser generates and the user passes to us
	ssh_tokens       = map[string]SSH_TokenInfo{}
	ssh_tokens_mutex sync.RWMutex
	//
	tokens          sync.Map
	SaveTokensMutex sync.Mutex
)

// Next comments will embed files into executable during compile time
//
//go:embed www/index.html
var embed_index_html []byte

//go:embed www/NotInWhitelist.html
var NotInWhitelist_PAGE string

//go:embed www/502.html
var embed_502_html []byte

//go:embed www/favicon.svg
var embed_favicon []byte

func main() {
	loadConfig()

	if cfg.SSH.Enabled && len(authorized_keys) == 0 {
		log.Print(yellow("Zero authorized keys. SSH server will no start"))
		cfg.SSH.Enabled = false
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
	if (syscall.Getuid() == 0) && cfg.DropPrivileges {
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
