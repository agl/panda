package main

import (
	"bufio"
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"net"
	"net/http"
	"os"
	"runtime"

	"code.google.com/p/go.crypto/nacl/secretbox"
	"code.google.com/p/go.crypto/scrypt"
	"code.google.com/p/go.net/proxy"
)

var secret *string = flag.String("secret", "", "The PANDA secret")
var keyFile *string = flag.String("key-file", "", "The file containing the data to exchange")
var server *string = flag.String("server", "panda-key-exchange.appspot.com:443", "The address of the PANDA server")
var useTLS *bool = flag.Bool("tls", true, "Whether to use TLS to contact the server")
var torProxy *string = flag.String("tor-proxy", "127.0.0.1:9050", "The address of the Tor SOCKS proxy, or the empty string to connect directly")

func deriveKey(result chan []byte, secret string) {
	keySlice, err := scrypt.Key([]byte(secret), nil, 1<<18, 20, 1, 32)
	if err != nil {
		panic(err)
	}
	result <- keySlice
}

func main() {
	runtime.GOMAXPROCS(2)
	flag.Parse()

	if len(*secret) == 0 {
		fmt.Fprintf(os.Stderr, "The shared secret must be given as --secret\n")
		os.Exit(2)
	}
	if len(*keyFile) == 0 {
		fmt.Fprintf(os.Stderr, "The path to a find containing the public key material to exchange must be given as --key-file\n")
		os.Exit(2)
	}

	pubKeyBytes, err := ioutil.ReadFile(*keyFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to read key file: %s\n", err)
		os.Exit(2)
	}

	const maxBody = 4096
	if limit := maxBody - 24 - secretbox.Overhead; len(pubKeyBytes) > limit {
		fmt.Fprintf(os.Stderr, "--key-file is too large (%d bytes of a maximum of %d)\n", len(pubKeyBytes), limit)
		os.Exit(2)
	}

	// Run scrypt on a goroutine so that we can overlap it with the network
	// delay.
	keyChan := make(chan []byte)
	go deriveKey(keyChan, *secret)

	var dialer proxy.Dialer
	dialer = proxy.Direct
	if len(*torProxy) > 0 {
		fmt.Fprintf(os.Stderr, "Using SOCKS5 proxy at %s\n", *torProxy)
		dialer, err = proxy.SOCKS5("tcp", *torProxy, nil, dialer)
		if err != nil {
			panic(err)
		}
	}

	fmt.Fprintf(os.Stderr, "Starting TCP connection to %s\n", *server)
	rawConn, err := dialer.Dial("tcp", *server)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to connect to server: %s\n", err)
		os.Exit(2)
	}

	var conn net.Conn
	if *useTLS {
		hostname, _, err := net.SplitHostPort(*server)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Failed to split %s into host and post: %s\n", *server, err)
			os.Exit(2)
		}
		tlsConn := tls.Client(rawConn, &tls.Config{
			ServerName: hostname,
		})
		fmt.Fprintf(os.Stderr, "Starting TLS handshake\n")
		if err := tlsConn.Handshake(); err != nil {
			rawConn.Close()
			fmt.Fprintf(os.Stderr, "TLS handshake failed: %s\n", err)
			os.Exit(2)
		}
		conn = tlsConn
	} else {
		conn = rawConn
	}
	defer conn.Close()

	var keySlice []byte
	select {
	case keySlice = <-keyChan:
	default:
		fmt.Fprintf(os.Stderr, "Waiting for key derivation to complete. This may take some time.\n")
		keySlice = <-keyChan
	}
	var key [32]byte
	copy(key[:], keySlice)

	mac := hmac.New(sha256.New, key[:])
	mac.Write(pubKeyBytes)
	nonceSlice := mac.Sum(nil)
	var nonce [24]byte
	copy(nonce[:], nonceSlice)

	box := make([]byte, len(nonce)+secretbox.Overhead+len(pubKeyBytes))
	copy(box, nonce[:])
	secretbox.Seal(box[len(nonce):len(nonce)], pubKeyBytes, &nonce, &key)

	h := sha256.New()
	h.Write(key[:])
	tag := h.Sum(nil)

	body := bytes.NewReader(box)
	request, err := http.NewRequest("POST", "http://"+*server+"/exchange/"+hex.EncodeToString(tag), body)
	if err != nil {
		panic(err)
	}
	request.ContentLength = int64(len(box))
	request.Header.Add("Content-Type", "application/octet-stream")

	request.Write(conn)
	fmt.Fprintf(os.Stderr, "Request sent. Waiting for HTTP reply\n")
	replyReader := bufio.NewReader(conn)

	response, err := http.ReadResponse(replyReader, request)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error reading reply from server: %s\n", err)
		os.Exit(2)
	}

	switch response.StatusCode {
	case 409:
		fmt.Fprintf(os.Stderr, "The transaction failed because this key has been used recently by two other parties.\n")
		os.Exit(2)
	case 204:
		fmt.Fprintf(os.Stderr, "Material submitted, but the other party has yet to start the process. Try again later with the same arguments.\n")
		os.Exit(1)
	case 200:
		r := &io.LimitedReader{R: response.Body, N: maxBody + 1}
		body, err := ioutil.ReadAll(r)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error reading from server: %s\n", err)
			os.Exit(2)
		}
		if len(body) > maxBody {
			fmt.Fprintf(os.Stderr, "Reply from server is too large\n")
			os.Exit(2)
		}
		if len(body) < len(nonce)+secretbox.Overhead {
			fmt.Fprintf(os.Stderr, "Reply from server is too short to be valid: %x\n", body)
			os.Exit(2)
		}
		copy(nonce[:], body)
		unsealed, ok := secretbox.Open(nil, body[len(nonce):], &nonce, &key)
		if !ok {
			fmt.Fprintf(os.Stderr, "Failed to authenticate reply from server\n")
			os.Exit(2)
		}
		os.Stdout.Write(unsealed)
	default:
		fmt.Fprintf(os.Stderr, "HTTP error from server: %s\n", response.Status)
		io.Copy(os.Stderr, response.Body)
		os.Exit(2)
	}
}
