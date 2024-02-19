package main

import (
	"log"
	"strings"
)

type filteredLogger struct {
	Logger *log.Logger
}

func (fl *filteredLogger) Write(p []byte) (n int, err error) {
	msg := string(p)

	// https://github.com/golang/go/issues/26918
	if strings.HasPrefix(msg, "http: TLS handshake error") {
		return len(p), nil
	}

	return fl.Logger.Writer().Write(p)
}

// Less spam from bots/crawlers
func newServerErrorLog() *log.Logger {
	if cfg.FilterSpam {
		return log.New(&filteredLogger{log.Default()}, "", 0)
	} else {
		return log.Default()
	}
}
