package main

import (
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
)

// Add proper ANSI escape codes to render it green-colored in a supported terminal
func red(in string) string {
	return fmt.Sprintf("\033[0;31m%s\033[0;0m", in)
}

func green(in string) string {
	return fmt.Sprintf("\033[0;32m%s\033[0;0m", in)
}

func blue(in string) string {
	return fmt.Sprintf("\033[0;34m%s\033[0;0m", in)
}

func yellow(in string) string {
	return fmt.Sprintf("\033[0;33m%s\033[0;0m", in)
}

// Expand tilde ~ to home dir
func expandTilde(path string) string {
	user_dir, err := os.UserHomeDir()
	if err != nil {
		log.Fatal(err)
	}
	if strings.HasPrefix(path, "~/") {
		return filepath.Join(user_dir, path[2:])
	}
	return path
}

// Replaces
//
//	"@Jipok" = ""
//
// To
//
//	"@Jipok" = "Jipok"
func handleTelegramUsers(telegramUsers map[string]string) []string {
	var newUsers []string
	for telegram_name, jauth_name := range telegramUsers {
		if jauth_name == "" {
			jauth_name, _ = strings.CutPrefix(telegram_name, "@")
			cfg.TelegramUsers[telegram_name] = jauth_name
		}
		newUsers = append(newUsers, jauth_name)
	}
	return newUsers
}

func removeDuplicates(slice []string) []string {
	keys := make(map[string]bool)
	list := []string{}
	for _, entry := range slice {
		if _, value := keys[entry]; !value {
			keys[entry] = true
			list = append(list, entry)
		}
	}
	return list
}
