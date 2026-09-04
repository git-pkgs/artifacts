package artifacts

import (
	"strings"
	"testing"

	"github.com/opencontainers/go-digest"
)

var (
	testSHA256 = digest.Digest("sha256:" + strings.Repeat("a", 64))
	testSHA384 = digest.Digest("sha384:" + strings.Repeat("b", 96))
	testSHA512 = digest.Digest("sha512:" + strings.Repeat("c", 128))
)

func TestNewCanonicalizesPURL(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{name: "npm", input: "pkg:npm/lodash@4.17.21", want: "pkg:npm/lodash@4.17.21"},
		{name: "scoped npm", input: "pkg:npm/%40babel/core@7.24.0", want: "pkg:npm/%40babel/core@7.24.0"},
		{name: "PyPI wheel", input: "pkg:pypi/charset-normalizer@3.3.2", want: "pkg:pypi/charset-normalizer@3.3.2"},
		{name: "Go module", input: "pkg:golang/github.com/gin-gonic/gin@v1.10.0", want: "pkg:golang/github.com/gin-gonic/gin@v1.10.0"},
		{
			name:  "qualifier order",
			input: "pkg:npm/example@1.0.0?repository_url=https%3A%2F%2Fregistry.example.com&arch=arm64",
			want:  "pkg:npm/example@1.0.0?arch=arm64&repository_url=https:%2F%2Fregistry.example.com",
		},
		{
			name:  "percent encoding",
			input: "pkg:npm/%40scope/package@1.0.0?tag=one%20two",
			want:  "pkg:npm/%40scope/package@1.0.0?tag=one%20two",
		},
		{name: "subpath", input: "pkg:golang/example.com/module@v1.2.3#cmd/tool", want: "pkg:golang/example.com/module@v1.2.3#cmd/tool"},
		{name: "encoded subpath", input: "pkg:npm/example@1.0.0#docs%20and%20examples", want: "pkg:npm/example@1.0.0#docs%20and%20examples"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			artifact, err := New(test.input, testSHA256, 42, "package.tgz", "application/octet-stream")
			if err != nil {
				t.Fatalf("New() error = %v", err)
			}
			if artifact.PURL != test.want {
				t.Errorf("PURL = %q, want %q", artifact.PURL, test.want)
			}
			if err := artifact.Validate(); err != nil {
				t.Errorf("Validate() error = %v", err)
			}
		})
	}
}

func TestNewAcceptsSupportedDigests(t *testing.T) {
	for _, contentDigest := range []digest.Digest{testSHA256, testSHA384, testSHA512} {
		t.Run(contentDigest.Algorithm().String(), func(t *testing.T) {
			artifact, err := New("pkg:npm/example@1.0.0", contentDigest, 1, "", "")
			if err != nil {
				t.Fatalf("New() error = %v", err)
			}
			if artifact.Digest != contentDigest {
				t.Errorf("Digest = %q, want %q", artifact.Digest, contentDigest)
			}
		})
	}
}

func TestNewRejectsInvalidPURL(t *testing.T) {
	tests := []struct {
		name  string
		value string
	}{
		{name: "empty"},
		{name: "malformed", value: "not-a-purl"},
		{name: "malformed encoding", value: "pkg:npm/example@1.0.0#docs%zz"},
		{name: "empty subpath segment", value: "pkg:npm/example@1.0.0#docs//examples"},
		{name: "current directory subpath", value: "pkg:npm/example@1.0.0#./docs"},
		{name: "parent directory subpath", value: "pkg:npm/example@1.0.0#../docs"},
		{name: "encoded parent directory subpath", value: "pkg:npm/example@1.0.0#%2E%2E/docs"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := New(test.value, testSHA256, 1, "", "")
			if err == nil {
				t.Fatal("New() error = nil")
			}
			if !strings.Contains(err.Error(), "PURL") {
				t.Errorf("error = %q, want PURL field", err)
			}
		})
	}
}

func TestNewRejectsInvalidDigest(t *testing.T) {
	tests := []struct {
		name  string
		value digest.Digest
	}{
		{name: "empty"},
		{name: "malformed", value: "sha256:not-hex"},
		{name: "unsupported", value: "md5:d41d8cd98f00b204e9800998ecf8427e"},
		{name: "wrong length", value: "sha256:abcd"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := New("pkg:npm/example@1.0.0", test.value, 1, "", "")
			if err == nil {
				t.Fatal("New() error = nil")
			}
			if !strings.Contains(err.Error(), "digest") {
				t.Errorf("error = %q, want digest field", err)
			}
		})
	}
}

func TestNewSize(t *testing.T) {
	tests := []struct {
		name    string
		size    int64
		wantErr bool
	}{
		{name: "zero byte", size: 0},
		{name: "positive", size: 1},
		{name: "negative", size: -1, wantErr: true},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := New("pkg:pypi/example@1.0.0", testSHA256, test.size, "", "")
			if (err != nil) != test.wantErr {
				t.Fatalf("New() error = %v, wantErr %v", err, test.wantErr)
			}
			if err != nil && !strings.Contains(err.Error(), "size") {
				t.Errorf("error = %q, want size field", err)
			}
		})
	}
}

func TestNewRetainsOptionalLabels(t *testing.T) {
	tests := []struct {
		name      string
		filename  string
		mediaType string
	}{
		{name: "empty"},
		{name: "set", filename: "example-1.0.0-py3-none-any.whl", mediaType: "application/zip"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			artifact, err := New("pkg:pypi/example@1.0.0", testSHA256, 100, test.filename, test.mediaType)
			if err != nil {
				t.Fatalf("New() error = %v", err)
			}
			if artifact.Filename != test.filename {
				t.Errorf("Filename = %q, want %q", artifact.Filename, test.filename)
			}
			if artifact.MediaType != test.mediaType {
				t.Errorf("MediaType = %q, want %q", artifact.MediaType, test.mediaType)
			}
		})
	}
}

func TestDigestCanDescribeDifferentPackages(t *testing.T) {
	first, err := New("pkg:npm/example@1.0.0", testSHA256, 100, "example.tgz", "application/gzip")
	if err != nil {
		t.Fatal(err)
	}
	second, err := New("pkg:pypi/example@1.0.0", testSHA256, 100, "example.whl", "application/zip")
	if err != nil {
		t.Fatal(err)
	}

	if first.Digest != second.Digest {
		t.Fatal("artifacts should retain their shared digest")
	}
	if first.PURL == second.PURL || first.Filename == second.Filename {
		t.Fatal("artifacts should retain their distinct package metadata")
	}
}

func TestValidateRejectsZeroValue(t *testing.T) {
	var artifact Artifact
	if err := artifact.Validate(); err == nil {
		t.Fatal("Validate() error = nil")
	} else if !strings.Contains(err.Error(), "PURL") {
		t.Errorf("error = %q, want PURL field", err)
	}
}

func TestValidateRejectsNonCanonicalPURL(t *testing.T) {
	artifact := Artifact{
		PURL:   "pkg:npm/example@1.0.0?repository_url=https%3A%2F%2Fregistry.example.com&arch=arm64",
		Digest: testSHA256,
		Size:   1,
	}
	if err := artifact.Validate(); err == nil {
		t.Fatal("Validate() error = nil")
	} else if !strings.Contains(err.Error(), "PURL") {
		t.Errorf("error = %q, want PURL field", err)
	}
}

func TestNewAndValidateReturnConsistentErrors(t *testing.T) {
	tests := []struct {
		name     string
		artifact Artifact
		field    string
	}{
		{
			name:     "PURL",
			artifact: Artifact{PURL: "not-a-purl", Digest: testSHA256, Size: 1},
			field:    "PURL",
		},
		{
			name:     "digest",
			artifact: Artifact{PURL: "pkg:npm/example@1.0.0", Digest: "sha256:abcd", Size: 1},
			field:    "digest",
		},
		{
			name:     "size",
			artifact: Artifact{PURL: "pkg:npm/example@1.0.0", Digest: testSHA256, Size: -1},
			field:    "size",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, newErr := New(test.artifact.PURL, test.artifact.Digest, test.artifact.Size, "", "")
			validateErr := test.artifact.Validate()
			if newErr == nil || validateErr == nil {
				t.Fatalf("New() error = %v, Validate() error = %v", newErr, validateErr)
			}
			if newErr.Error() != validateErr.Error() {
				t.Errorf("New() error = %q, Validate() error = %q", newErr, validateErr)
			}
			if !strings.Contains(newErr.Error(), test.field) {
				t.Errorf("error = %q, want field %q", newErr, test.field)
			}
		})
	}
}
