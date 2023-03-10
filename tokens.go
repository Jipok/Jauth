package main

import (
	"io/ioutil"
	"log"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

type Token_Info struct {
	username string
	// This counter shows how many TOKEN_COUNTDOWN_TIMER are left before the token is revoked
	// Updated to the maximum(cfg.MaxNonActiveTime) value on any use of the token
	countdown int
}

const (
	TOKEN_LENGTH          = 24 // Not provided to the frontend
	TOKEN_COUNTDOWN_TIMER = time.Hour
	TOKENS_FILE           = "jauth-tokens.txt"
)

var (
	tokens          sync.Map
	SaveTokensMutex sync.Mutex
)

func AddToken(username string, token string) bool {
	if len(token) != TOKEN_LENGTH {
		return false
	}
	// Check for duplicate
	_, in_tokens := tokens.Load(token)
	if in_tokens {
		return false
	}
	tokenInfo := Token_Info{username: username, countdown: cfg.MaxNonActiveTime}
	// Store safe to use with goroutines
	tokens.Store(token, tokenInfo)
	log.Printf("New token for '%s': %s", username, token)
	// Persistent save for each new token
	saveTokens()

	return true
}

// From global var `tokens` to file TOKENS_FILE
func saveTokens() {
	// This is the only function that all goroutines can call
	// Using synchronization to avoid chance of overwriting a file simultaneously
	SaveTokensMutex.Lock()
	defer SaveTokensMutex.Unlock()
	// We use a temporary file so as not to damage the list of tokens in case
	// program suddenly closes before it has time to write everything to file
	file, err := ioutil.TempFile(".", TOKENS_FILE+"-")
	if err != nil {
		log.Printf(red("Failed to save tokens!\n%s"), err)
		return
	}
	tokens.Range(func(token, tokenInfo interface{}) bool {
		p1 := token.(string)
		p2 := tokenInfo.(Token_Info).username
		p3 := strconv.Itoa(tokenInfo.(Token_Info).countdown)
		file.WriteString(p1 + "\t" + p2 + "\t" + p3 + "\n")
		return true
	})
	// Flush data to disk
	file.Sync()
	if err != nil {
		log.Printf(red("Failed to save tokens!\n%s"), err)
		return
	}
	file.Close()
	if err != nil {
		log.Printf(red("Failed to save tokens!\n%s"), err)
		return
	}
	// This allows us to make saving an atomic operation
	os.Rename(file.Name(), TOKENS_FILE)
	if err != nil {
		log.Printf(red("Failed to save tokens!\n%s"), err)
	}
}

// From file TOKENS_FILE to global var `tokens`
func loadTokens() error {
	tokens_data, err := ioutil.ReadFile(TOKENS_FILE)
	if err != nil {
		return err
	}
	// Each line contains one Token_Info
	for _, line := range strings.Split(string(tokens_data), "\n") {
		if line == "" {
			continue
		}
		// token,username,countdown separated by TAB
		parts := strings.Split(line, "\t")
		if len(parts) < 3 {
			log.Printf("Invalid line in %s: %s", TOKENS_FILE, line)
			continue
		}
		token := parts[0]
		username := parts[1]
		countdown, err := strconv.Atoi(parts[2])
		if err != nil {
			log.Fatal(err)
		}
		// Drop token for deleted user
		in_tg := false
		for _, v := range cfg.TelegramUsers {
			if v == username {
				in_tg = true
			}
		}
		_, in_ssh := authorized_keys[username]
		if !in_tg && !in_ssh {
			log.Printf("Tokens for %s revoked as user is no longer registered", username)
			continue
		}
		tokenInfo := Token_Info{username: username, countdown: countdown}
		tokens.Store(token, tokenInfo)
	}
	return nil
}

// This goroutine tracks non active tokens
func tokensCountdown() {
	// Run every TOKEN_COUNTDOWN_TIMER time
	for range time.Tick(TOKEN_COUNTDOWN_TIMER) {
		// Iterate over tokens
		tokens.Range(func(token, tokenInfoInterface interface{}) bool {
			tokenInfo := tokenInfoInterface.(Token_Info)
			tokenInfo.countdown -= 1
			// Drop non active tokens
			if tokenInfo.countdown == 0 {
				log.Printf("Revoked an expired token for a user: %s", tokenInfo.username)
				tokens.Delete(token)
				return true
			}
			tokens.Store(token, tokenInfo)
			return true
		})
		saveTokens()
	}
}

// Go don't have method to calc len of sync.Map  -_-
// https://github.com/golang/go/issues/20680
func len_tokens() int {
	len_tokens := 0
	tokens.Range(func(_, _ interface{}) bool {
		len_tokens += 1
		return true
	})
	return len_tokens
}
