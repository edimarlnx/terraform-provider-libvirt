package uri

import (
	"fmt"
	"github.com/trzsz/trzsz-ssh/tssh"
	"golang.org/x/net/proxy"
	"log"
	"net"
	"net/url"
	"os"
	"os/user"
	"strings"

	"github.com/kevinburke/ssh_config"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
	"golang.org/x/crypto/ssh/knownhosts"
)

const (
	defaultSSHPort           = "22"
	defaultSSHKeyPath        = "${HOME}/.ssh/id_rsa"
	defaultSSHKnownHostsPath = "${HOME}/.ssh/known_hosts"
	defaultSSHConfigFile     = "${HOME}/.ssh/config"
	defaultSSHAuthMethods    = "agent,privkey"
)

func (u *ConnectionURI) parseAuthMethods() []ssh.AuthMethod {
	q := u.Query()

	authMethods := q.Get("sshauth")
	if authMethods == "" {
		authMethods = defaultSSHAuthMethods
	}

	sshKeyPath := q.Get("keyfile")
	if sshKeyPath == "" {
		sshKeyPath = defaultSSHKeyPath
	}

	auths := strings.Split(authMethods, ",")
	result := make([]ssh.AuthMethod, 0)
	for _, v := range auths {
		switch v {
		case "agent":
			socket := os.Getenv("SSH_AUTH_SOCK")
			if socket == "" {
				continue
			}
			conn, err := net.Dial("unix", socket)
			// Ignore error, we just fall back to another auth method
			if err != nil {
				log.Printf("[ERROR] Unable to connect to SSH agent: %v", err)
				continue
			}
			agentClient := agent.NewClient(conn)
			result = append(result, ssh.PublicKeysCallback(agentClient.Signers))
		case "privkey":
			sshKey, err := os.ReadFile(os.ExpandEnv(sshKeyPath))
			if err != nil {
				log.Printf("[ERROR] Failed to read ssh key: %v", err)
				continue
			}

			signer, err := ssh.ParsePrivateKey(sshKey)
			if err != nil {
				log.Printf("[ERROR] Failed to parse ssh key: %v", err)
			}
			result = append(result, ssh.PublicKeys(signer))
		case "ssh-password":
			if sshPassword, ok := u.User.Password(); ok {
				result = append(result, ssh.Password(sshPassword))
			} else {
				log.Printf("[ERROR] Missing password in userinfo of URI authority section")
			}
		default:
			// For future compatibility it's better to just warn and not error
			log.Printf("[WARN] Unsupported auth method: %s", v)
		}
	}

	return result
}

func (u *ConnectionURI) dialSSH() (net.Conn, error) {
	q := u.Query()
	sshConfigFilePath := q.Get("ssh_config")
	if sshConfigFilePath == "" {
		sshConfigFilePath = defaultSSHConfigFile
	}
	sshConfigFile, err := os.Open(os.ExpandEnv(sshConfigFilePath))
	if err != nil {
		log.Printf("[WARN] Failed to open ssh config file: %v", err)
	}

	sshcfg, err := ssh_config.Decode(sshConfigFile)
	if err != nil {
		log.Printf("[WARN] Failed to parse ssh config file: %v", err)
	}

	authMethods := u.parseAuthMethods()
	if len(authMethods) < 1 {
		return nil, fmt.Errorf("could not configure SSH authentication methods")
	}

	knownHostsPath := q.Get("knownhosts")
	knownHostsVerify := q.Get("known_hosts_verify")
	doVerify := q.Get("no_verify") == ""

	if knownHostsVerify == "ignore" {
		doVerify = false
	}

	if knownHostsPath == "" {
		knownHostsPath = defaultSSHKnownHostsPath
	}

	hostKeyCallback := ssh.InsecureIgnoreHostKey()
	if doVerify {
		cb, err := knownhosts.New(os.ExpandEnv(knownHostsPath))
		if err != nil {
			return nil, fmt.Errorf("failed to read ssh known hosts: %w", err)
		}
		hostKeyCallback = cb
	}

	username := u.User.Username()
	if username == "" {
		sshu, err := sshcfg.Get(u.Host, "User")
		log.Printf("[DEBUG] SSH User: %v", sshu)
		if err != nil {
			log.Printf("[DEBUG] ssh user: system username")
			u, err := user.Current()
			if err != nil {
				return nil, fmt.Errorf("unable to get username: %w", err)
			}
			sshu = u.Username
		}
		username = sshu
	}

	cfg := ssh.ClientConfig{
		User:            username,
		HostKeyCallback: hostKeyCallback,
		Auth:            authMethods,
		Timeout:         dialTimeout,
	}

	sshClient, err := u.sshClient(cfg)
	if err != nil {
		log.Fatal(err)
	}

	address := q.Get("socket")
	if address == "" {
		address = defaultUnixSock
	}

	c, err := sshClient.Dial("unix", address)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to libvirt on the remote host: %w", err)
	}

	return c, nil
}

func (u *ConnectionURI) sshClient(cfg ssh.ClientConfig) (*ssh.Client, error) {
	q := u.Query()
	sshControlPath := q.Get("SSHControlPath")
	proxyURI := proxyByEnvVar()
	port := u.Port()
	if port == "" {
		port = defaultSSHPort
	}
	if sshControlPath == "" && proxyURI == "" {
		return ssh.Dial("tcp", fmt.Sprintf("%s:%s", u.Hostname(), port), &cfg)
	}
	var proxyConn net.Conn
	if sshControlPath != "" {
		sshControlPath = os.ExpandEnv(strings.Replace(sshControlPath, "~", "$HOME", 1))
		_, err := os.Stat(sshControlPath)
		if err != nil || os.IsNotExist(err) {
			return nil, err
		}
		controlSocketConn, err := net.Dial("unix", sshControlPath)
		if err != nil {
			return nil, err
		}
		controlConn, chans, reqs, err := tssh.NewControlClientConn(controlSocketConn)
		if err != nil {
			return nil, err
		}
		sshControlClient := ssh.NewClient(controlConn, chans, reqs)
		sshControlClientConn, err := sshControlClient.Dial("tcp", fmt.Sprintf("%s:%s", u.Hostname(), port))
		if err != nil {
			return nil, err
		}
		proxyConn = sshControlClientConn
	} else {
		parsedProxyURI, err := url.Parse(proxyURI)
		if err != nil || os.IsNotExist(err) {
			return nil, err
		}
		dialer, err := proxy.SOCKS5(parsedProxyURI.Scheme, parsedProxyURI.Host, nil, proxy.Direct)
		if err != nil {
			return nil, err
		}
		socketConn, err := dialer.Dial("tcp", u.Host)
		if err != nil {
			return nil, err
		}
		proxyConn = socketConn
	}

	ncc, chans, reqs, err := ssh.NewClientConn(proxyConn, fmt.Sprintf("%s:%s", u.Hostname(), port), &cfg)
	if err != nil {
		return nil, err
	}
	cli := ssh.NewClient(ncc, chans, reqs)
	return cli, nil
}

func proxyByEnvVar() string {
	proxyURL := os.Getenv("HTTP_PROXY")
	if proxyURL != "" {
		return proxyURL
	}
	return os.Getenv("ALL_PROXY")
}
