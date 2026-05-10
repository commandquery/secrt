package main

import (
	"bytes"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"strings"
)

// MergeEnv merges the current process environment with overrides from an environment object.
func MergeEnv(secretEnv []byte) ([]string, error) {
	env := os.Environ()
	idx := make(map[string]int, len(env))
	for i, entry := range env {
		if k, _, ok := strings.Cut(entry, "="); ok {
			idx[strings.ToUpper(k)] = i
		}
	}

	for n, line := range strings.Split(string(secretEnv), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		k, _, ok := strings.Cut(line, "=")
		if !ok {
			return nil, fmt.Errorf("line %d: missing '='", n+1)
		}
		if i, found := idx[strings.ToUpper(k)]; found {
			env[i] = line
		} else {
			env = append(env, line)
			idx[strings.ToUpper(k)] = len(env) - 1
		}
	}

	return env, nil
}

// CmdRun runs a shell command with the given secret as the environment (or stdin).
func CmdRun(config *Config, endpoint *Endpoint, args []string) error {

	flags := flag.NewFlagSet("run", flag.ContinueOnError)
	envSecretId := flags.String("env", "", "use the given JSON secret as the environment")
	stdinSecretId := flags.String("stdin", "", "use the given secret for stdin")
	if err := flags.Parse(args); err != nil {
		return fmt.Errorf("unable to parse flags: %w", err)
	}

	// the command to run.
	args = flags.Args()
	if len(args) == 0 {
		return fmt.Errorf("no command to run")
	}

	secretEnv, err := FindMessage(config, endpoint, *envSecretId)
	if err != nil {
		return fmt.Errorf("unable to find environment: %w", err)
	}

	stdin, err := FindMessage(config, endpoint, *stdinSecretId)
	if err != nil {
		return fmt.Errorf("unable to find stdin: %w", err)
	}

	cmd := exec.Command(args[0], args[1:]...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	if *envSecretId != "" {
		cmd.Env, err = MergeEnv(secretEnv.Cleartext)
		if err != nil {
			return err
		}
	}

	if *stdinSecretId != "" {
		cmd.Stdin = bytes.NewReader(stdin.Cleartext)
	} else {
		cmd.Stdin = os.Stdin
	}

	return cmd.Run()
}
