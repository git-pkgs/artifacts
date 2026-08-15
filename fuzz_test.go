package artifacts

import (
	"reflect"
	"testing"

	"github.com/opencontainers/go-digest"
)

func FuzzNew(f *testing.F) {
	f.Add("pkg:npm/example@1.0.0", testSHA256.String(), int64(1), "example.tgz", "application/gzip")
	f.Add("pkg:pypi/example@1.0.0", testSHA384.String(), int64(0), "", "")
	f.Add("pkg:golang/example.com/module@v1.2.3?goos=linux#cmd/tool", testSHA512.String(), int64(42), "module.zip", "application/zip")
	f.Add("", "", int64(-1), "../package", "not a media type")

	f.Fuzz(func(t *testing.T, packageURL, contentDigest string, size int64, filename, mediaType string) {
		artifact, err := New(packageURL, digest.Digest(contentDigest), size, filename, mediaType)
		if err != nil {
			return
		}
		if err := artifact.Validate(); err != nil {
			t.Fatalf("New() returned an invalid Artifact: %v", err)
		}

		reconstructed, err := New(artifact.PURL, artifact.Digest, artifact.Size, artifact.Filename, artifact.MediaType)
		if err != nil {
			t.Fatalf("New() rejected a previously accepted Artifact: %v", err)
		}
		if !reflect.DeepEqual(reconstructed, artifact) {
			t.Fatalf("reconstruction changed Artifact from %#v to %#v", artifact, reconstructed)
		}
	})
}
