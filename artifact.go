package artifacts

import (
	_ "crypto/sha256"
	_ "crypto/sha512"
	"fmt"
	"net/url"
	"strings"

	"github.com/git-pkgs/purl"
	"github.com/opencontainers/go-digest"
)

// Artifact describes a completed package file.
type Artifact struct {
	PURL      string
	Digest    digest.Digest
	Size      int64
	Filename  string
	MediaType string
}

// New constructs a validated Artifact and stores the canonical package URL.
func New(packageURL string, contentDigest digest.Digest, size int64, filename, mediaType string) (Artifact, error) {
	canonicalPURL, err := validate(packageURL, contentDigest, size)
	if err != nil {
		return Artifact{}, err
	}

	return Artifact{
		PURL:      canonicalPURL,
		Digest:    contentDigest,
		Size:      size,
		Filename:  filename,
		MediaType: mediaType,
	}, nil
}

// Validate checks that an Artifact has valid package coordinates, digest, and size.
func (artifact Artifact) Validate() error {
	canonicalPURL, err := validate(artifact.PURL, artifact.Digest, artifact.Size)
	if err != nil {
		return err
	}
	if artifact.PURL != canonicalPURL {
		return fmt.Errorf("PURL: is not canonical, want %q", canonicalPURL)
	}
	return nil
}

func validate(packageURL string, contentDigest digest.Digest, size int64) (string, error) {
	parsed, err := purl.Parse(packageURL)
	if err != nil {
		return "", fmt.Errorf("PURL: %w", err)
	}
	if parsed.Subpath != "" {
		parsed.Subpath, err = canonicalSubpath(parsed.Subpath)
		if err != nil {
			return "", err
		}
	}
	canonicalPURL := parsed.String()
	if err := contentDigest.Validate(); err != nil {
		return "", fmt.Errorf("digest: %w", err)
	}
	if size < 0 {
		return "", fmt.Errorf("size: must be zero or greater")
	}

	return canonicalPURL, nil
}

func canonicalSubpath(subpath string) (string, error) {
	decode := strings.Contains(subpath, "%")
	remainder := subpath
	var canonical strings.Builder
	if decode {
		canonical.Grow(len(subpath))
	}

	for first := true; ; first = false {
		rawSegment, next, found := strings.Cut(remainder, "/")
		segment, err := url.PathUnescape(rawSegment)
		if err != nil {
			return "", fmt.Errorf("PURL subpath: %w", err)
		}
		if segment == "" {
			return "", fmt.Errorf("PURL subpath: segment %q is empty", rawSegment)
		}
		if segment == "." || segment == ".." {
			return "", fmt.Errorf("PURL subpath: segment %q is not allowed", segment)
		}
		if strings.Contains(segment, "/") {
			return "", fmt.Errorf("PURL subpath: segment %q contains a slash", segment)
		}
		if decode {
			if !first {
				canonical.WriteByte('/')
			}
			canonical.WriteString(segment)
		}
		if !found {
			break
		}
		remainder = next
	}

	if decode {
		return canonical.String(), nil
	}
	return subpath, nil
}
