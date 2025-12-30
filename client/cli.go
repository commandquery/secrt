package client

import (
	"fmt"
	"os"

	"golang.org/x/term"
)

func Confirm(prompt string) bool {
	if !term.IsTerminal(int(os.Stdin.Fd())) {
		return false
	}

	fmt.Printf("%s [y/n] ", prompt)

	oldState, err := term.MakeRaw(int(os.Stdin.Fd()))
	if err != nil {
		return false
	}
	defer term.Restore(int(os.Stdin.Fd()), oldState)

	var b [1]byte
	if _, err = os.Stdin.Read(b[:]); err != nil {
		return false
	}

	fmt.Println() // newline after keypress

	return b[0] == 'y' || b[0] == 'Y'
}
