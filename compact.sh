#!/usr/bin/env bash
CGO_ENABLED=0 go build -ldflags "-s -w" && upx jauth
CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -o jauth_arm64 -ldflags "-s -w" && upx jauth_arm64
