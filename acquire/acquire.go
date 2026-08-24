// Package acquire coordinates package artifact resolution, downloading,
// integrity verification, and storage.
package acquire

import (
	"context"
	"errors"
	"fmt"
	"io"

	"github.com/git-pkgs/artifacts"
	"github.com/git-pkgs/integrity"
	"github.com/git-pkgs/purl"
	"github.com/opencontainers/go-digest"
)

const maxInt64 = int64(1<<63 - 1)

var (
	// ErrNotFound reports that a store has no artifact matching a request.
	ErrNotFound = errors.New("artifact not found")
	// ErrOffline reports that acquisition would require an upstream request.
	ErrOffline = errors.New("artifact unavailable offline")
	// ErrTooLarge reports that an artifact exceeds the configured byte limit.
	ErrTooLarge = errors.New("artifact exceeds size limit")
)

// Request identifies one package artifact. Filename and Integrity may narrow
// a version that has several published files.
type Request struct {
	PURL      string
	Filename  string
	Integrity integrity.SRI
}

// Source describes the upstream file selected for a request. Integrity is
// used when the request did not supply lockfile integrity metadata.
type Source struct {
	URL       string
	Filename  string
	MediaType string
	Integrity integrity.SRI
}

// Download is a streaming upstream response. Size is -1 when unavailable.
type Download struct {
	Body      io.ReadCloser
	Size      int64
	MediaType string
}

// Entry is a completed artifact opened from a Store.
type Entry struct {
	Artifact artifacts.Artifact
	Body     io.ReadCloser
}

// Result is an acquired artifact and a reader positioned at its first byte.
type Result struct {
	Artifact artifacts.Artifact
	Body     io.ReadCloser
	Cached   bool
}

// Options controls one acquisition.
type Options struct {
	Offline  bool
	MaxBytes int64
}

// Resolver selects an upstream file for a canonical, versioned request.
type Resolver interface {
	Resolve(context.Context, Request) (Source, error)
}

// Fetcher opens an upstream URL. The returned body belongs to the caller.
type Fetcher interface {
	Fetch(context.Context, string) (*Download, error)
}

// Store finds completed artifacts and creates private staging writes.
//
// Open must return ErrNotFound when no completed artifact matches every
// populated Request field. A Stage must remain unavailable through Open until
// Commit succeeds.
type Store interface {
	Open(context.Context, Request) (*Entry, error)
	Stage(context.Context, Request, Source) (Stage, error)
}

// Stage receives unverified bytes. Commit publishes them and returns a fresh
// reader. Discard removes an unpublished stage.
type Stage interface {
	io.Writer
	Commit(context.Context, artifacts.Artifact) (io.ReadCloser, error)
	Discard(context.Context) error
}

// Service acquires package artifacts through supplied resolver, fetcher, and
// store implementations.
type Service struct {
	Resolver Resolver
	Fetcher  Fetcher
	Store    Store
}

// Acquire returns a matching stored artifact or resolves and fetches one.
func (service Service) Acquire(ctx context.Context, request Request, options Options) (*Result, error) {
	request, err := normalizeRequest(request)
	if err != nil {
		return nil, err
	}
	if err := validateOptions(options); err != nil {
		return nil, err
	}

	entry, err := service.open(ctx, request)
	if err != nil {
		return nil, err
	}
	if entry != nil {
		return resultFromEntry(entry, options.MaxBytes)
	}
	if options.Offline {
		return nil, fmt.Errorf("%w: %s", ErrOffline, request.PURL)
	}
	if service.Resolver == nil {
		return nil, fmt.Errorf("acquire artifact: nil resolver")
	}

	source, err := service.Resolver.Resolve(ctx, request)
	if err != nil {
		return nil, fmt.Errorf("resolve artifact %s: %w", request.PURL, err)
	}
	return service.acquireSource(ctx, request, source, options, true)
}

// AcquireFrom returns a matching stored artifact or fetches the supplied
// source. It supports callers that already obtained an exact artifact URL.
func (service Service) AcquireFrom(ctx context.Context, request Request, source Source, options Options) (*Result, error) {
	request, err := normalizeRequest(request)
	if err != nil {
		return nil, err
	}
	if err := validateOptions(options); err != nil {
		return nil, err
	}
	return service.acquireSource(ctx, request, source, options, false)
}

func (service Service) acquireSource(
	ctx context.Context,
	request Request,
	source Source,
	options Options,
	requestAlreadyMissed bool,
) (*Result, error) {
	source, err := normalizeSource(source)
	if err != nil {
		return nil, err
	}
	lookup, err := requestForSource(request, source)
	if err != nil {
		return nil, err
	}
	entry, err := service.openSource(ctx, request, lookup, requestAlreadyMissed)
	if err != nil {
		return nil, err
	}
	if entry != nil {
		return resultFromEntry(entry, options.MaxBytes)
	}
	if options.Offline {
		return nil, fmt.Errorf("%w: %s", ErrOffline, request.PURL)
	}
	if service.Fetcher == nil {
		return nil, fmt.Errorf("acquire artifact: nil fetcher")
	}

	download, err := service.Fetcher.Fetch(ctx, source.URL)
	if err != nil {
		return nil, fmt.Errorf("fetch artifact %s: %w", request.PURL, err)
	}
	if err := validateDownload(request.PURL, download, options); err != nil {
		return nil, err
	}
	defer func() { _ = download.Body.Close() }()
	return service.stageDownload(ctx, request, lookup, source, download, options)
}

func (service Service) stageDownload(
	ctx context.Context,
	request Request,
	lookup Request,
	source Source,
	download *Download,
	options Options,
) (*Result, error) {
	stage, err := service.Store.Stage(ctx, lookup, source)
	if err != nil {
		return nil, fmt.Errorf("stage artifact %s: %w", request.PURL, err)
	}
	if stage == nil {
		return nil, fmt.Errorf("stage artifact %s: nil stage", request.PURL)
	}
	committed := false
	defer func() {
		if !committed {
			_ = stage.Discard(context.WithoutCancel(ctx))
		}
	}()

	hashed, err := copyAndVerify(stage, download.Body, lookup.Integrity, options.MaxBytes)
	if err != nil {
		return nil, fmt.Errorf("verify artifact %s: %w", request.PURL, err)
	}
	sha256Digest, err := resultDigest(hashed, integrity.SHA256)
	if err != nil {
		return nil, fmt.Errorf("hash artifact %s: %w", request.PURL, err)
	}

	mediaType := source.MediaType
	if download.MediaType != "" {
		mediaType = download.MediaType
	}
	artifact, err := artifacts.New(
		request.PURL,
		digest.Digest("sha256:"+sha256Digest.Hex()),
		hashed.Bytes,
		lookup.Filename,
		mediaType,
	)
	if err != nil {
		return nil, fmt.Errorf("describe artifact %s: %w", request.PURL, err)
	}

	body, err := stage.Commit(ctx, artifact)
	if err != nil {
		return nil, fmt.Errorf("commit artifact %s: %w", request.PURL, err)
	}
	if body == nil {
		return nil, fmt.Errorf("commit artifact %s: nil body", request.PURL)
	}
	committed = true
	return &Result{Artifact: artifact, Body: body}, nil
}

func (service Service) openSource(
	ctx context.Context,
	request Request,
	lookup Request,
	requestAlreadyMissed bool,
) (*Entry, error) {
	if requestAlreadyMissed && sameRequest(request, lookup) {
		return nil, nil
	}
	return service.open(ctx, lookup)
}

func validateDownload(packageURL string, download *Download, options Options) error {
	if download == nil {
		return fmt.Errorf("fetch artifact %s: nil download", packageURL)
	}
	if download.Body == nil {
		return fmt.Errorf("fetch artifact %s: nil body", packageURL)
	}
	if download.Size < -1 {
		_ = download.Body.Close()
		return fmt.Errorf("fetch artifact %s: invalid size %d", packageURL, download.Size)
	}
	if options.MaxBytes > 0 && download.Size > options.MaxBytes {
		_ = download.Body.Close()
		return fmt.Errorf("%w: declared %d bytes, limit %d", ErrTooLarge, download.Size, options.MaxBytes)
	}
	return nil
}

func copyAndVerify(
	destination io.Writer,
	source io.Reader,
	expected integrity.SRI,
	maxBytes int64,
) (integrity.Result, error) {
	reader, err := integrity.NewReader(source, digestAlgorithms(expected)...)
	if err != nil {
		return integrity.Result{}, err
	}
	content := io.Reader(reader)
	if maxBytes > 0 && maxBytes < maxInt64 {
		content = io.LimitReader(reader, maxBytes+1)
	}
	written, err := io.Copy(destination, content)
	if err != nil {
		return integrity.Result{}, err
	}
	if maxBytes > 0 && written > maxBytes {
		return integrity.Result{}, fmt.Errorf("%w: read more than %d bytes", ErrTooLarge, maxBytes)
	}

	result := reader.Result()
	if !result.Complete {
		return integrity.Result{}, fmt.Errorf("incomplete stream")
	}
	if len(expected) > 0 {
		if err := result.Verify(expected); err != nil {
			return integrity.Result{}, err
		}
	}
	return result, nil
}

func (service Service) open(ctx context.Context, request Request) (*Entry, error) {
	if service.Store == nil {
		return nil, fmt.Errorf("acquire artifact: nil store")
	}
	entry, err := service.Store.Open(ctx, request)
	if errors.Is(err, ErrNotFound) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("open artifact %s: %w", request.PURL, err)
	}
	if entry == nil {
		return nil, fmt.Errorf("open artifact %s: nil entry", request.PURL)
	}
	if entry.Body == nil {
		return nil, fmt.Errorf("open artifact %s: nil body", request.PURL)
	}
	if err := entry.Artifact.Validate(); err != nil {
		_ = entry.Body.Close()
		return nil, fmt.Errorf("open artifact %s: invalid metadata: %w", request.PURL, err)
	}
	if entry.Artifact.PURL != request.PURL {
		_ = entry.Body.Close()
		return nil, fmt.Errorf("open artifact %s: store returned PURL %s", request.PURL, entry.Artifact.PURL)
	}
	if request.Filename != "" && entry.Artifact.Filename != request.Filename {
		_ = entry.Body.Close()
		return nil, fmt.Errorf("open artifact %s: store returned filename %q", request.PURL, entry.Artifact.Filename)
	}
	return entry, nil
}

func normalizeRequest(request Request) (Request, error) {
	parsed, err := purl.Parse(request.PURL)
	if err != nil {
		return Request{}, fmt.Errorf("acquire artifact: PURL: %w", err)
	}
	if parsed.Version == "" {
		return Request{}, fmt.Errorf("acquire artifact: PURL has no version")
	}
	if parsed.Subpath != "" {
		return Request{}, fmt.Errorf("acquire artifact: PURL has a subpath")
	}
	if err := validateIntegrity(request.Integrity); err != nil {
		return Request{}, fmt.Errorf("acquire artifact: integrity: %w", err)
	}
	request.PURL = parsed.String()
	return request, nil
}

func normalizeSource(source Source) (Source, error) {
	if source.URL == "" {
		return Source{}, fmt.Errorf("acquire artifact: source URL is empty")
	}
	if err := validateIntegrity(source.Integrity); err != nil {
		return Source{}, fmt.Errorf("acquire artifact: source integrity: %w", err)
	}
	return source, nil
}

func validateIntegrity(metadata integrity.SRI) error {
	for index, item := range metadata {
		if _, err := integrity.ParseHex(item.Algorithm(), item.Hex()); err != nil {
			return fmt.Errorf("entry %d: %w", index+1, err)
		}
	}
	return nil
}

func validateOptions(options Options) error {
	if options.MaxBytes < 0 {
		return fmt.Errorf("acquire artifact: max bytes must be zero or greater")
	}
	return nil
}

func requestForSource(request Request, source Source) (Request, error) {
	if request.Filename != "" && source.Filename != "" && request.Filename != source.Filename {
		return Request{}, fmt.Errorf(
			"acquire artifact: source filename %q does not match request filename %q",
			source.Filename,
			request.Filename,
		)
	}
	if request.Filename == "" {
		request.Filename = source.Filename
	}
	if len(request.Integrity) == 0 {
		request.Integrity = source.Integrity
	}
	return request, nil
}

func sameRequest(first, second Request) bool {
	return first.PURL == second.PURL &&
		first.Filename == second.Filename &&
		integrity.FormatSRI(first.Integrity) == integrity.FormatSRI(second.Integrity)
}

func digestAlgorithms(expected integrity.SRI) []integrity.Algorithm {
	algorithms := make([]integrity.Algorithm, 0, len(expected)+1)
	algorithms = append(algorithms, integrity.SHA256)
	for _, item := range expected {
		algorithms = append(algorithms, item.Algorithm())
	}
	return algorithms
}

func resultDigest(result integrity.Result, algorithm integrity.Algorithm) (integrity.Digest, error) {
	for _, item := range result.Digests {
		if item.Algorithm() == algorithm {
			return item, nil
		}
	}
	return integrity.Digest{}, fmt.Errorf("no %s digest", algorithm)
}

func resultFromEntry(entry *Entry, maxBytes int64) (*Result, error) {
	if maxBytes > 0 && entry.Artifact.Size > maxBytes {
		_ = entry.Body.Close()
		return nil, fmt.Errorf(
			"%w: stored %d bytes, limit %d",
			ErrTooLarge,
			entry.Artifact.Size,
			maxBytes,
		)
	}
	return &Result{
		Artifact: entry.Artifact,
		Body:     entry.Body,
		Cached:   true,
	}, nil
}
