package artifacts_test

import (
	"fmt"

	"github.com/git-pkgs/artifacts"
	"github.com/opencontainers/go-digest"
)

func ExampleNew() {
	artifact, err := artifacts.New(
		"pkg:npm/lodash@4.17.21",
		digest.Digest("sha256:9e15e8133c3c58e28e70fb5b3f62f74c2fb542f4391fb4128a4d5656d57e7606"),
		318961,
		"lodash-4.17.21.tgz",
		"application/gzip",
	)
	if err != nil {
		panic(err)
	}

	fmt.Println(artifact.PURL)
	fmt.Println(artifact.Digest)
	// Output:
	// pkg:npm/lodash@4.17.21
	// sha256:9e15e8133c3c58e28e70fb5b3f62f74c2fb542f4391fb4128a4d5656d57e7606
}

func ExampleArtifact_Validate() {
	artifact := artifacts.Artifact{
		PURL:      "pkg:pypi/charset-normalizer@3.3.2",
		Digest:    digest.Digest("sha256:f30c3d80b4c84420e54e1b5f80e5d1db6f39ccf62f5c2b9ea308c67c9cb4f4c1"),
		Size:      142373,
		Filename:  "charset_normalizer-3.3.2-py3-none-any.whl",
		MediaType: "application/zip",
	}

	fmt.Println(artifact.Validate() == nil)
	// Output: true
}
