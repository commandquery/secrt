package main

import (
	"fmt"
	"slices"
	"strings"

	"github.com/kelseyhightower/envconfig"
)

const (
	EnrolFile = "file"
	EnrolMail = "mail"
)

var Config struct {
	DatabaseDSN     string `split_words:"true"`
	Store           string `split_words:"true"`
	ChallengeSize   int    `split_words:"true" default:"20"` // Incrementing by 1 *doubles* the complexity
	PathPrefix      string `split_words:"true" default:"/"`
	EnrolAction     string `split_words:"true" default:"mail"` // What to do for enrolment requests
	EnrolFile       string `split_words:"true"`                // Optional filename
	SMTPDisable     bool   `split_words:"true" default:"false"`
	SMTPServer      string `split_words:"true" default:"smtp.postmarkapp.com"`
	SMTPUsername    string `split_words:"true"`
	SMTPPassword    string `split_words:"true"`
	SMTPHeaderKey   string `split_words:"true" default:"X-PM-Message-Stream"`
	SMTPHeaderValue string `split_words:"true" default:"outbound"`
}

func initConfig() error {
	if err := envconfig.Process("secrt", &Config); err != nil {
		return err
	}

	if !strings.HasSuffix(Config.PathPrefix, "/") {
		Config.PathPrefix += "/"
	}

	if !slices.Contains([]string{EnrolFile, EnrolMail}, Config.EnrolAction) {
		return fmt.Errorf("invalid enrolment action: %s", Config.EnrolAction)
	}

	if Config.EnrolAction == EnrolFile && Config.EnrolFile == "" {
		return fmt.Errorf("SECRT_ENROL_ACTION is 'file' but no SECRT_ENROL_FILE is specified")
	}

	return nil
}
