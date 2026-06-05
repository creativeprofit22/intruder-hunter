package main

import (
	"os"

	"github.com/creativeprofit22/intruder-hunter/internal/cli"
)

func main() {
	os.Exit(cli.Execute(os.Stdout, os.Stderr, os.Args[1:]))
}
