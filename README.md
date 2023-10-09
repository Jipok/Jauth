# Jauth
Jauth is a lightweight SSL/TLS reverse proxy with authorization. Great for protect your self-hosted applications. Moreover, it offers SSO for simpler login management.

![Login screenshot](screenshot.png?raw=true)

# Features
* Single binary executable with no dependencies
* SSL/TLS encryption using autogenerated self-signed certificates or Let's Encrypt
* User authorization via SSH or Telegram
* Optional Singe Sign-On
* Minimal configuration required
* Whitelist-based access control
* Support for multiple domain names
* Security for bloated and vulnerable modern applications
* Doesn't use any Telegram bot API
* No passwords. No registration

# Getting Started
1. Download the latest release:
```bash
wget https://github.com/Jipok/Jauth/releases/latest/download/jauth
```

2. Make executable:
```bash
chmod +x ./jauth
```

3. Run `./jauth`

Without the configuration, there will be the following behavior:
* Generate a self-signed certificate valid for one year. It will be saved in the current directory and used on restart.
* Run web server on `0.0.0.0:80` which will redirect all incoming connections to port `443`
* Run web server on `0.0.0.0:443` with generated certificate. It accepts connections from any domain or directly by ip address. Displays the login page.
* Run ssh server on `0.0.0.0:2222` for authorization. The list of authorized keys and their corresponding usernames is taken from `~/.ssh/authorized_keys`. Server key from `~/.ssh/id_rsa`
* After authorization, requests will be redirected to `127.0.0.1:8080`

# Configuration
By default, the server tries to open the `./jauth.toml` file. You can specify any path/name as the first command line argument.

## Simple but useful config example
```toml
# Use Let's Encrypt
Certificate.Type = "autocert"
SSO = "g.jipok.undo.it"
[TelegramUsers]
    # Telegram Nick or ID = Login for services behind jauth
    # ID is a safe way because it never changes
    354339153 = "Jipok"
    # But using a username is more convenient. Need to add @
    "@Jipok" = "Jipok"
    # Username on right can be omitted, so telegram one will be used
    "@Jipok" = ""
    87654321 = "Other User"
    "@SomeFriend" = "Friend1"
[[Domains]] # Paperless NGX
    domain = "p.jipok.undo.it"
    target = "8080" # Will be `127.0.0.1:8080`
[[Domains]] # Grist
    domain = "g.jipok.undo.it"
    # You can redirect to any domain/ip
    target = "not.localhost:8081"
    # Some applications use e-mail for identification. Add suffix to all logins:
    UserSuffix = "@local"
    # By default every user has access to every domain. Restrict access:
    Whitelist = ["Jipok", "Friend1"]
    WidgetBotName = "JipokSelfHosted_bot"
    WidgetBotToken = "9876543210:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"

```
## Tips
* To be able to authorize via telegram, you need to register your own bot. [It's simple](https://core.telegram.org/bots#how-do-i-create-a-bot). `WidgetBotName` and `WidgetBotToken` must be received from the telegram bot [@botfather](https://t.me/BotFather). You also need to run the `/setdomain` command for this bot and specify the appropriate domain. Telegram will only allow authorization from this domain. **jauth** does not use a bot in any way. The token is needed only for authorization validation, the api is not called.
* One telegram bot = one domain.
* Each domain will require(from LE) its own certificate. This process is fast, but not instantaneous. Unfortunately, there may be no information about the process in the logs. You can just wait a little (30 seconds) and try to open the page in the browser.
* The certificates will be saved in the `./jauth-autocert` folder.
* Login via ssh is enabled by default. The standard authorized_keys file format is used: each line contains a public key and a username. You can safely use your `~/.ssh/authorized_keys` (default) from the system ssh server. You can also easily change the username specified there to the desired one, for sshd it means almost nothing.
* The list of authorized users is preserved between restarts in `./jauth-tokens.txt`
* An authenticated user's username is passed to the server through the `Remote-User` HTTP header.
* There is a `github-key-import.sh` script that allows for search and quick appending of SSH keys from a GitHub profile. It requires fzf and jq.

## Full configuration example
```toml
# A more detailed SSH configuration is provided below
SSH.Enabled = false # Default true
# Used if target not specifies in some [[Domains]] section
# And for direct access via IP address in manual or self-signed mode
DefaultTarget = "8080"
# If true will drop privileges if started from root. 
# Will not be able to save state(tokens) between restarts.
DropPrivileges = false 
# Interface to listen
Listen = "0.0.0.0"
# Start server on 80 port that will redirect all to 443 port
RedirectHTTP = true
# Time (in hours) after which an inactive session will be logged out.
MaxNonActiveTime = 30
# URL for log out
LogoutURL = "/jauth-logout"
# The page that is given for authorization. You can download index.html from
# the repository and modify the design, then specify this file.
# If empty, the built-in default is used.
CustomPage = ""
# Single Sing-On. It's really just the default value for the LoginFrom option
# on every domain. See its description below.
SSO = ""

[SSH]
    Enabled = true
    Port = "2222"
    ServerKey = "~/.ssh/id_rsa"
    AuthorizedKeys = "~/.ssh/authorized_keys"
[Certificate]
    # Type can be:
    #   autocert - use Let's Encrypt
    #   self-signed - autogenerate
    #   manual - specify certificate. Example:
    Type = "manual" # Default self-signed
	Cert = "some-cert.crt" # Default "self-signed.crt"
	Key = "some-cert.key" # Default "self-signed.key"

[[Domains]]
    # Must not be empty
    domain = ""
    # If empty, will use DefaultTarget option 
    target = ""
    # Some applications use e-mail for identification
    UserSuffix = ""
    # List of users who will be allowed to use site. 
    # The rest will get NotInWhitelist.html
    Whitelist = []
    # If empty, then the telegram login widget will be hidden
    WidgetBotName = ""
    WidgetBotToken = ""
    # This is the domain to which user will be redirected for authorization.
    # In addition to Single Sing-On function, it is also necessary in order
    # not to produce a lot of telegram bots, since telegrams are allowed to
    # log in through the bot on only one domain. An empty value means that
    # the current domain will be used.
    LoginFrom = ""
    # If true, authorization will be disabled. Jauth will act as ssl-proxy
    NoAuth = false
```

# Thanks to
* [SSH As Authentication For Web Applications](https://github.com/lukevers/ssh-as-authentication-for-web-applications)
* [SSL-proxy](https://github.com/suyashkumar/ssl-proxy) project
* Rich GO ecosystem that has an ssh implementation

# Contributing

I am a lover of minimalism (in the style of [suckless](https://suckless.org/philosophy/)). So for me the project is mostly finished. If you want to add some feature, then start a discussion before writing the code, as I can simply dismiss the idea.