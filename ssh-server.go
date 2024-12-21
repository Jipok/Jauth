package main

import (
	"bufio"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"os"
	"strings"
	"time"
	"unicode"

	"golang.org/x/crypto/ssh"
)

type SSH_TokenInfo struct {
	// These and ssh_token are provided by ssh
	username string
	// These are provided for ssh back
	browserAddr  string
	browserAgent string
	browserLink  string
}

func startSshServer() {
	sshConfig := &ssh.ServerConfig{
		PublicKeyCallback: publicKeyCallback,
	}

	// Read server keys
	privateBytes, err := ioutil.ReadFile(cfg.SSH.ServerKey)
	if err != nil {
		log.Printf(red("Failed to load SSH server private key: %s :: ")+err.Error(), cfg.SSH.ServerKey)
		log.Fatal("You can generate new keys with ", green("`ssh-keygen`"))
	}
	// Parse
	signer, err := ssh.ParsePrivateKey(privateBytes)
	if err != nil {
		log.Fatal(red("Failed to parse SSH server private key: ") + err.Error())
	}
	sshConfig.AddHostKey(signer)
	// Print fingerprint in OpenSSH style
	fingerprint := sha256.Sum256(signer.PublicKey().Marshal())
	fingerprintBase64 := base64.StdEncoding.EncodeToString(fingerprint[:])
	log.Print("SSH key fingerprint is SHA256:" + blue(fingerprintBase64))

	// Once a ServerConfig has been configured, connections can be accepted.
	address := cfg.Listen + ":" + cfg.SSH.Port
	listener, err := net.Listen("tcp", address)
	if err != nil {
		log.Fatalf("failed to listen on %s", address)
	}
	defer listener.Close()
	log.Printf("SSH server listening on %s", listener.Addr().String())

	for {
		tcpConn, err := listener.Accept()
		if err != nil {
			log.Printf("failed to accept incoming connection (%s)", err)
			continue
		}
		// Will also call publicKeyCallback which will authenticate the user
		// Returns an error if the user is not in the `authorized_keys`
		sshConn, channels, _, err := ssh.NewServerConn(tcpConn, sshConfig)
		if err != nil {
			// TODO Filter it
			// SSH failed to handshake: ssh: no common algorithm for host key; client offered: [sk-ecdsa-sha2-nistp256@openssh.com], server offered: [rsa-sha2-256 rsa-sha2-512 ssh-rsa]
			if cfg.FilterSpam && !strings.Contains(err.Error(), "ssh") {
				continue
			}
			log.Printf("SSH failed to handshake: %s", err)
			continue
		}

		// Seems next can some time. Not block listening loop
		go handleChannels(*sshConn, channels)
	}
}

// Checks if the public key is in `authorized_keys` list
func publicKeyCallback(sshConn ssh.ConnMetadata, remoteKey ssh.PublicKey) (*ssh.Permissions, error) {
	log.Printf("Trying to auth: %s (%s::%s) - %s ", sshConn.User(), sshConn.ClientVersion(), remoteKey.Type(), sshConn.RemoteAddr())
	// TODO Do not show knowledge of public keys, somehow require the client to confirm the private key
	for _, localKey := range authorized_keys {
		// Make sure the key types match
		if remoteKey.Type() != localKey.keyType {
			continue
		}
		// Make sure every byte of the key matches up
		array1 := remoteKey.Marshal()
		array2 := localKey.keyData
		if len(array1) != len(array2) {
			continue
		}
		// We avoid instantaneous comparison failure to avoid timing attacks
		// I don't know if this actually works.
		equal := true
		for i := range array1 {
			if array1[i] != array2[i] {
				equal = false
			}
		}
		if !equal {
			continue
		}
		// Now we know user
		log.Printf("Public key match: %s", localKey.username)
		// TODO can client send Extensions?
		perm := ssh.Permissions{Extensions: make(map[string]string)}
		perm.Extensions["username"] = localKey.username
		return &perm, nil
	}
	return nil, errors.New(yellow("not authorized key"))
}

// This is called for already authenticated(via publicKeyCallback) users
// Handles receiving a token from the user
func handleChannels(sshConn ssh.ServerConn, channels <-chan ssh.NewChannel) {
	for newChannel := range channels {
		// Channels have a type, depending on the application level protocol intended.
		// In the case of a shell, the type is "session" and ServerShell may be used
		// to present a simple terminal interface.
		if t := newChannel.ChannelType(); t != "session" {
			newChannel.Reject(ssh.UnknownChannelType, fmt.Sprintf("unknown channel type: %s", t))
			continue
		}
		channel, requests, err := newChannel.Accept()
		if err != nil {
			log.Printf("could not accept channel (%s)", err)
			continue
		}
		// Get the previously(in publicKeyCallback) saved username
		username := sshConn.Permissions.Extensions["username"]
		fmt.Fprintf(channel, "Authenticated username: %s \n", username)

		// Typically SSH sessions have out-of-band requests such as "shell", "pty-req" and "env"
		// In our case, this is used to pass the tokens
		go func(in <-chan *ssh.Request) {
			for {
				select {
				case req := <-in:
					str := string(req.Payload)
					var sshToken = ""
					for _, rune := range str {
						if unicode.IsGraphic(rune) && !unicode.IsSpace(rune) {
							sshToken += string(rune)
						}
					}
					// Need to distinguish the token from other requests (like sendEnv)
					if (len(sshToken) != 7) || (sshToken[3] != '-') {
						continue
					}
					fmt.Fprintf(channel, "Provided token: %s \n", sshToken)
					// Lock and write to global var
					ssh_tokens_mutex.Lock()
					ssh_tokens[sshToken] = SSH_TokenInfo{username: username}
					ssh_tokens_mutex.Unlock()
					fmt.Fprint(channel, "Waiting for a request from the browser with this token")
					for {
						time.Sleep(100 * time.Millisecond)
						// Show the user some animation and check the connection at the same time
						_, err := fmt.Fprint(channel, ".")
						if err != nil {
							log.Printf(yellow("The SSH connection to user `%s` has been terminated"), username)
							break
						}
						// Lock and read from global var
						ssh_tokens_mutex.RLock()
						sshTokenInfo := ssh_tokens[sshToken]
						ssh_tokens_mutex.RUnlock()
						// When the browser requests a ssh_token check, the handleCheckAuth function
						// will add information about the browser
						if sshTokenInfo.browserLink != "" {
							fmt.Fprintf(channel, "\n") // After dots
							fmt.Fprintf(channel, green("Access granted!\n"))
							fmt.Fprintf(channel, "Browser: %s\n", sshTokenInfo.browserAgent)
							fmt.Fprintf(channel, "IP address: %s\n\n", sshTokenInfo.browserAddr)
							fmt.Fprintf(channel, "You can share access to this session via the link:\n"+blue("%s\n"), sshTokenInfo.browserLink)
							break
						}
					}
					// Send exit code: 0 - success
					// 4 zeros because answer must be uint32 (4 bytes)
					channel.SendRequest("exit-status", false, []byte{0, 0, 0, 0})
					channel.Close()
					sshConn.Close()
					// Lock and modify global var
					ssh_tokens_mutex.Lock()
					delete(ssh_tokens, sshToken)
					ssh_tokens_mutex.Unlock()
					return
				case <-time.After(5 * time.Second):
					fmt.Fprint(channel, red("Timeout: Token not provided\n"))
					channel.Close()
					sshConn.Close()
					return
				}
			}
		}(requests)
	}
}

// Load `filename` as authorized_keys
func loadAuthorizedKeys(filename string) []string {
	var newUsers []string
	// Parse file
	file, err := os.Open(filename)
	if err != nil {
		log.Fatalf("Can't open authorized_keys: %s", filename)
	}
	defer file.Close()
	// Read line by line
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		if len(scanner.Text()) < 2 {
			continue
		}
		key, name, _, _, err := ssh.ParseAuthorizedKey(scanner.Bytes())
		if err != nil {
			log.Fatal(err)
		}
		authorized_keys = append(authorized_keys, SSH_Info{
			keyType:  key.Type(),
			keyData:  key.Marshal(),
			username: name})
		newUsers = append(newUsers, name)
	}
	return newUsers
}
