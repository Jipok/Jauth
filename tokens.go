package main

import (
	"crypto/rand"
	"io/ioutil"
	"log"
	"math/big"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

type Token_Info struct {
	// This counter shows how many TOKEN_COUNTDOWN_TIMER are left before the token is revoked
	// Updated to the maximum(cfg.MaxNonActiveTime) value on any use of the token
	countdown int
	username  string
	history   []Token_Usage_History
}

type Token_Usage_History struct {
	time      int64
	ip        string
	useragent string
}

const (
	TOKEN_LENGTH          = 24
	TOKEN_COUNTDOWN_TIMER = time.Hour
	TOKENS_FILE           = "jauth-tokens.txt"
)

var (
	tokens          sync.Map
	SaveTokensMutex sync.Mutex
)

// GenerateRandomString returns a securely generated random string.
// It will return an error if the system's secure random
// number generator fails to function correctly, in which
// case the caller should not continue. Source:
// https://gist.github.com/dopey/c69559607800d2f2f90b1b1ed4e550fb
func GenerateRandomString(n int) string {
	const letters = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
	ret := make([]byte, n)
	for i := 0; i < n; i++ {
		num, err := rand.Int(rand.Reader, big.NewInt(int64(len(letters))))
		if err != nil {
			log.Fatal("Fatal at GenerateRandomString: ", err)
		}
		ret[i] = letters[num.Int64()]
	}
	return string(ret)
}

// Generate and store new token
func newToken(username string, ip string, useragent string) string {
	token := strconv.FormatInt(time.Now().Unix(), 10)
	token += "-"
	token += GenerateRandomString(TOKEN_LENGTH)
	// Check for duplicate. Must be almost impossible. But let's make sure
	_, in_tokens := tokens.Load(token)
	if in_tokens {
		return newToken(username, ip, useragent)
	}
	hEntry := Token_Usage_History{
		time:      time.Now().Unix(),
		ip:        ip,
		useragent: useragent,
	}
	history := []Token_Usage_History{hEntry}
	tokenInfo := Token_Info{
		username:  username,
		countdown: cfg.MaxNonActiveTime,
		history:   history,
	}
	// Store safe to use with goroutines
	tokens.Store(token, tokenInfo)
	log.Printf("New token for '%s': %s", username, token)
	// Persistent save for each new token
	go saveTokens()
	return token
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
	tokens.Range(func(tokenPointer, tokenInfoPointer interface{}) bool {
		// Information about the token takes one line and is separated by tabs
		tokenInfo := tokenInfoPointer.(Token_Info)
		p1 := tokenPointer.(string)
		p2 := strconv.Itoa(tokenInfo.countdown)
		p3 := tokenInfo.username
		file.WriteString(p1 + "\t" + p2 + "\t" + p3 + "\n")
		// Historical information is also tab-separated and takes up one line per
		// entry, but starts with a tab to distinguish it from a token.
		for _, v := range tokenInfo.history {
			p1 = strconv.FormatInt(v.time, 10)
			p2 = v.ip
			p3 = v.useragent
			file.WriteString("\t" + p1 + "\t" + p2 + "\t" + p3 + "\n")
		}
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
	var tokenInfo Token_Info
	lines := strings.Split(string(tokens_data), "\n")
	// Each line contains one Token_Info
	for i := 0; i < len(lines); i++ {
		if lines[i] == "" {
			continue
		}
		// token,countdown,username separated by TAB
		parts := strings.SplitN(lines[i], "\t", 3)
		if len(parts) < 3 {
			log.Printf("Invalid line in %s:%d: %s", TOKENS_FILE, i, lines[i])
			continue
		}
		token := parts[0]
		countdown, err := strconv.Atoi(parts[1])
		username := parts[2]
		if err != nil {
			log.Fatal(err)
		}
		// Parse token history. Each entry starts with tab
		history := []Token_Usage_History{}
		var hEntry Token_Usage_History
		for (i+1 < len(lines)) && (len(lines[i+1]) > 0) && (lines[i+1][0] == '\t') {
			i += 1
			parts = strings.SplitN(lines[i], "\t", 4)
			if len(parts) < 4 {
				log.Printf("Invalid line in %s:%d: %s", TOKENS_FILE, i, lines[i])
				continue
			}
			hEntry.time, err = strconv.ParseInt(parts[1], 10, 64)
			if err != nil {
				log.Printf("Invalid line in %s:%d: %s", TOKENS_FILE, i, lines[i])
				continue
			}
			hEntry.ip = parts[2]
			hEntry.useragent = parts[3]
			history = append(history, hEntry)
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
			log.Printf("Token for %s revoked as user is no longer registered", username)
			continue
		}
		tokenInfo = Token_Info{username: username, countdown: countdown, history: history}
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
