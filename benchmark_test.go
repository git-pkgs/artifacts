package artifacts

import "testing"

const (
	benchmarkSimplePURL    = "pkg:npm/lodash@4.17.21"
	benchmarkQualifiedPURL = "pkg:npm/%40example/package@1.2.3?arch=arm64&download_url=https%3A%2F%2Fregistry.example.com%2Fpackage.tgz&os=linux&repository_url=https%3A%2F%2Fregistry.example.com#dist"
)

var (
	benchmarkArtifact Artifact
	benchmarkError    error
)

func BenchmarkNew(b *testing.B) {
	for _, packageURL := range []string{benchmarkSimplePURL, benchmarkQualifiedPURL} {
		b.Run(packageURL, func(b *testing.B) {
			b.ReportAllocs()
			for b.Loop() {
				benchmarkArtifact, benchmarkError = New(packageURL, testSHA256, 318961, "package.tgz", "application/gzip")
			}
		})
	}
}

func BenchmarkValidate(b *testing.B) {
	for _, packageURL := range []string{benchmarkSimplePURL, benchmarkQualifiedPURL} {
		artifact, err := New(packageURL, testSHA256, 318961, "package.tgz", "application/gzip")
		if err != nil {
			b.Fatal(err)
		}

		b.Run(packageURL, func(b *testing.B) {
			b.ReportAllocs()
			for b.Loop() {
				benchmarkError = artifact.Validate()
			}
		})
	}
}
