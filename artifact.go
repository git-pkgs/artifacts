package artifacts

import (
	_ "crypto/sha512"
	"fmt"
	"net/url"

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
		parsed.Subpath, err = url.PathUnescape(parsed.Subpath)
		if err != nil {
			return "", fmt.Errorf("PURL subpath: %w", err)
		}
	}
	canonicalPURL := parsed.String()
	reparsed, err := purl.Parse(canonicalPURL)
	if err != nil {
		return "", fmt.Errorf("PURL canonical form: %w", err)
	}
	if reparsed.Subpath != "" {
		reparsed.Subpath, err = url.PathUnescape(reparsed.Subpath)
		if err != nil {
			return "", fmt.Errorf("PURL canonical subpath: %w", err)
		}
	}
	if reparsed.String() != canonicalPURL {
		return "", fmt.Errorf("PURL: canonical form is not stable")
	}
	if err := contentDigest.Validate(); err != nil {
		return "", fmt.Errorf("digest: %w", err)
	}
	if size < 0 {
		return "", fmt.Errorf("size: must be zero or greater")
	}

	return canonicalPURL, nil
}
