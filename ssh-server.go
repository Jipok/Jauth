package main

import (
	"bufio"
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"os"
	"sync"
	"unicode"

	"golang.org/x/crypto/ssh"
)

/*
This global variable is only used in two methods: publicKeyCallback, handleChannels.
Such a workaround is needed because there is no way to find out what public key
the user has when processing channels (the token is passed there). Although SSH
provides the User value, it cannot be changed and is passed from the user side.
And we need the ability to assign any username for the key
*/
var sshAddrToUsername sync.Map

func startSshServer() {
	sshConfig := &ssh.ServerConfig{
		PublicKeyCallback: publicKeyCallback,
	}

	// Read server keys
	privateBytes, err := ioutil.ReadFile(cfg.SSH.ServerKey)
	if err != nil {
		log.Printf("Failed to load SSH server private key: %s", cfg.SSH.ServerKey)
		log.Print("You can generate new keys with ", green("`ssh-keygen`"))
	}
	// Parse
	private, err := ssh.ParsePrivateKey(privateBytes)
	if err != nil {
		log.Fatal("Failed to parse SSH server private key")
	}
	sshConfig.AddHostKey(private)

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
			log.Printf("Failed to handshake: %s", err)
			continue
		}

		// Seems next can some time. Not block listening loop
		go handleChannels(sshConn, channels)
	}
}

// Checks if the public key is in `authorized_keys` list
func publicKeyCallback(sshConn ssh.ConnMetadata, remoteKey ssh.PublicKey) (*ssh.Permissions, error) {
	log.Printf("Trying to auth: %s (%s) - %s ", sshConn.User(), sshConn.ClientVersion(), sshConn.RemoteAddr())

	for username, localKey := range authorized_keys {
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
		sshAddrToUsername.Store(sshConn.RemoteAddr().String(), username)
		log.Printf("Public key math: %s", username)
		return nil, nil
	}
	return nil, errors.New("Not authorized key")
}

// This is called for already authenticated(via publicKeyCallback) users
// Handles receiving a token from the user
func handleChannels(sshConn ssh.ConnMetadata, channels <-chan ssh.NewChannel) {
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
		addr := sshConn.RemoteAddr().String()
		tmp, ok := sshAddrToUsername.Load(addr)
		// It shouldn't be possible. But we'll be safe
		if !ok {
			channel.Close()
		}
		// Deletion is not necessary for security, because even if user logs in
		// under a different name from same address, value in `map` will change.
		// And the call to this method always occurs after checking public key.
		// Just saves some memory
		sshAddrToUsername.Delete(addr)
		username := tmp.(string)

		// Print
		channel.Write([]byte(fmt.Sprintf("Authenticated username: %s \n", username)))

		// Typically SSH sessions have out-of-band requests such as "shell", "pty-req" and "env"
		// In our case, this is used to pass the tokens
		go func(in <-chan *ssh.Request) {
			for req := range in {
				str := string(req.Payload)
				var token = ""
				for _, rune := range str {
					if unicode.IsLetter(rune) || unicode.IsDigit(rune) || rune == '-' {
						token += string(rune)
					}
				}
				channel.Write([]byte(fmt.Sprintf("Provided token: %s \n", token)))

				if AddToken(username, token) {
					channel.Write([]byte(green("Access granted!\n")))
				} else {
					channel.Write([]byte(red("Access denied! Wrong token length or token already used\n")))
				}
				channel.Close()
			}
		}(requests)
	}
}

// Load `filename` as authorized_keys
func loadAuthorizedKeys(filename string) {
	// Parse file
	file, err := os.Open(filename)
	if err == nil {
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
			authorized_keys[name] = SSH_Info{key.Type(), key.Marshal(), nil}
		}
	} else {
		log.Fatalf("SSH: Can't open %s", filename)
	}
}
