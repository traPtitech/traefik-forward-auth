package main

import (
	"fmt"
	"github.com/sirupsen/logrus"
	tfa "github.com/traPtitech/traefik-forward-auth/internal"
	"net/http"
	"os"
	"strconv"
	"time"
)

func initConfigs(args []string) (*tfa.Config, *logrus.Logger) {
	// Parse options
	config := tfa.NewGlobalConfig(args)

	// Setup logger
	log := tfa.NewDefaultLogger()

	// Perform config validation
	config.Validate()

	return config, log
}

// serve mode
func serve() {
	config, log := initConfigs(os.Args[1:])

	// Build server
	server := tfa.NewServer()

	// Attach router to default server
	http.HandleFunc("/", server.RootHandler)

	// Start
	log.WithField("config", config).Debug("Starting with config")
	log.Infof("Listening on :%d", config.Port)
	log.Info(http.ListenAndServe(fmt.Sprintf(":%d", config.Port), nil))
}

// sign mode
func sign() {
	// Check arg counts
	if len(os.Args) < 4 {
		fmt.Printf("Usage: %v sign <user-name> <ttl-in-seconds> [options...]\n", os.Args[0])
		os.Exit(1)
	}

	_, _ = initConfigs(os.Args[4:])

	user := os.Args[2]
	ttlStr := os.Args[3]
	ttl, err := strconv.Atoi(ttlStr)
	if err != nil {
		fmt.Printf("TTL needs to be an integer: %s\n", ttlStr)
	}

	expiry := time.Now().Unix() + int64(ttl)
	token := tfa.SignToken(user, expiry)
	fmt.Println(token)
}

func main() {
	if len(os.Args) >= 2 && os.Args[1] == "sign" {
		// Manual token sign mode
		// Expect arg of: tfa sign user-name ttl-in-seconds [options...]
		sign()
	} else {
		// Normal server mode
		serve()
	}
}
