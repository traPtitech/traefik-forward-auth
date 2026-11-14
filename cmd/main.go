package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"net"
	"net/http"
	"os"
	"strconv"
	"time"

	"github.com/samber/lo"
	"github.com/sirupsen/logrus"
	tfa "github.com/traPtitech/traefik-forward-auth/internal"
	"github.com/traPtitech/traefik-forward-auth/internal/token"
)

func initConfigs(args []string) (*tfa.Config, *logrus.Logger) {
	// Parse flags
	_ = flag.CommandLine.Parse(args)

	// Parse options
	cfg := tfa.NewGlobalConfig(*config)

	// Setup logger
	log := tfa.NewDefaultLogger(cfg)

	return cfg, log
}

// serve mode
func serve() {
	cfg, log := initConfigs(os.Args[1:])

	// Build server
	server := tfa.NewServer()

	// Attach router to default server
	http.HandleFunc("/", server.RootHandler)

	// Start
	log.WithField("config", cfg).Debug("Starting with config")
	log.Infof("Listening on :%d", cfg.Port)
	log.Info(http.ListenAndServe(fmt.Sprintf(":%d", cfg.Port), nil))
}

// sign mode
func sign() {
	// Check arg counts
	if len(os.Args) < 5 {
		fmt.Printf("Usage: %v sign <host> <userinfo json> <ttl-in-seconds> [options...]\n", os.Args[0])
		os.Exit(1)
	}

	cfg, _ := initConfigs(os.Args[5:])

	host := os.Args[2]
	// The server compares the audience with the request host without its port.
	if _, _, err := net.SplitHostPort(host); err == nil {
		fmt.Printf("Host must not include a port: %s\n", host)
		return
	}
	userinfoStr := os.Args[3]
	ttlStr := os.Args[4]

	var userinfo any
	err := json.Unmarshal([]byte(userinfoStr), &userinfo)
	if err != nil {
		fmt.Printf("Error parsing userinfo json: %v\n", err)
		return
	}
	// Check that all info-fields exist
	for _, field := range cfg.InfoFields {
		_, ok := token.GetPathStr(userinfo, field)
		if !ok {
			fmt.Printf("Passed JSON does not contain field \"%v\", which is required from the \"info-fields\" config. Check the passed JSON or \"info-fields\" config?\n", field)
			return
		}
	}

	ttl, err := strconv.Atoi(ttlStr)
	if err != nil {
		fmt.Printf("TTL needs to be an integer: %s\n", ttlStr)
		return
	}

	expiry := time.Now().Add(time.Duration(ttl) * time.Second)
	tok := lo.Must(token.SignHostToken(userinfo, host, expiry, []byte(cfg.Secret)))
	fmt.Println(tok)
}

var config = flag.String("config", "", "Path to config file")

func main() {
	if len(os.Args) >= 2 && os.Args[1] == "sign" {
		// Manual token sign mode
		sign()
	} else {
		// Normal server mode
		serve()
	}
}
