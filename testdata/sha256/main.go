package main

import (
	"fmt"
	"os"

	"github.com/git-pkgs/artifacts"
	"github.com/opencontainers/go-digest"
)

func main() {
	_, err := artifacts.New(
		"pkg:npm/example@1.0.0",
		digest.Digest("sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"),
		1,
		"example.tgz",
		"application/gzip",
	)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
