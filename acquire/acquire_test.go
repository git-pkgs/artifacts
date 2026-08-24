package acquire

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/sha512"
	"errors"
	"fmt"
	"io"
	"strings"
	"testing"

	"github.com/git-pkgs/artifacts"
	"github.com/git-pkgs/integrity"
	"github.com/opencontainers/go-digest"
)

const testPURL = "pkg:npm/example@1.0.0"

func TestAcquireReturnsStoredArtifact(t *testing.T) {
	content := []byte("stored package")
	stored := testArtifact(t, testPURL, "example.tgz", content)
	store := &testStore{
		open: func(_ context.Context, request Request) (*Entry, error) {
			if request.PURL != testPURL {
				t.Errorf("Open PURL = %q, want %q", request.PURL, testPURL)
			}
			return &Entry{Artifact: stored, Body: io.NopCloser(bytes.NewReader(content))}, nil
		},
	}
	resolver := &testResolver{}
	fetcher := &testFetcher{}
	service := Service{Resolver: resolver, Fetcher: fetcher, Store: store}

	result, err := service.Acquire(context.Background(), Request{PURL: "pkg:NPM/example@1.0.0"}, Options{})
	if err != nil {
		t.Fatalf("Acquire() error = %v", err)
	}
	defer func() { _ = result.Body.Close() }()
	if !result.Cached {
		t.Error("Cached = false, want true")
	}
	if result.Artifact != stored {
		t.Errorf("Artifact = %+v, want %+v", result.Artifact, stored)
	}
	if got := readString(t, result.Body); got != string(content) {
		t.Errorf("Body = %q, want %q", got, content)
	}
	if resolver.calls != 0 || fetcher.calls != 0 {
		t.Errorf("resolver calls = %d, fetcher calls = %d, want zero", resolver.calls, fetcher.calls)
	}
}

func TestAcquisitionRejectsOversizeStoredArtifact(t *testing.T) {
	content := []byte("stored package")
	stored := testArtifact(t, testPURL, "example.tgz", content)
	tests := []struct {
		name string
		call func(Service) (*Result, error)
	}{
		{
			name: "Acquire",
			call: func(service Service) (*Result, error) {
				return service.Acquire(
					context.Background(),
					Request{PURL: testPURL},
					Options{MaxBytes: int64(len(content) - 1)},
				)
			},
		},
		{
			name: "AcquireFrom",
			call: func(service Service) (*Result, error) {
				return service.AcquireFrom(
					context.Background(),
					Request{PURL: testPURL},
					Source{URL: "https://registry.example/example.tgz"},
					Options{MaxBytes: int64(len(content) - 1)},
				)
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			body := &trackingBody{Reader: bytes.NewReader(content)}
			store := &testStore{
				open: func(context.Context, Request) (*Entry, error) {
					return &Entry{Artifact: stored, Body: body}, nil
				},
			}
			resolver := &testResolver{}
			fetcher := &testFetcher{}

			result, err := test.call(Service{Resolver: resolver, Fetcher: fetcher, Store: store})
			if !errors.Is(err, ErrTooLarge) {
				t.Fatalf("acquisition error = %v, want ErrTooLarge", err)
			}
			if result != nil {
				t.Errorf("result = %+v, want nil", result)
			}
			if !body.closed {
				t.Error("stored body was not closed")
			}
			if resolver.calls != 0 || fetcher.calls != 0 {
				t.Errorf("resolver calls = %d, fetcher calls = %d, want zero", resolver.calls, fetcher.calls)
			}
		})
	}
}

func TestAcquireOfflineMiss(t *testing.T) {
	store := missingStore()
	resolver := &testResolver{}
	service := Service{Resolver: resolver, Store: store}

	_, err := service.Acquire(context.Background(), Request{PURL: testPURL}, Options{Offline: true})
	if !errors.Is(err, ErrOffline) {
		t.Fatalf("Acquire() error = %v, want ErrOffline", err)
	}
	if resolver.calls != 0 {
		t.Errorf("resolver calls = %d, want zero", resolver.calls)
	}
}

func TestAcquireResolvesVerifiesAndCommits(t *testing.T) {
	content := []byte("downloaded package")
	requestIntegrity := testSRI(t, integrity.SHA512, content)
	wrongSourceIntegrity := testSRI(t, integrity.SHA256, []byte("different package"))
	source := Source{
		URL:       "https://registry.example/example.tgz",
		Filename:  "example.tgz",
		MediaType: "application/gzip",
		Integrity: wrongSourceIntegrity,
	}
	resolver := &testResolver{source: source}
	body := &trackingBody{Reader: bytes.NewReader(content)}
	fetcher := &testFetcher{download: &Download{
		Body:      body,
		Size:      int64(len(content)),
		MediaType: "application/x-gzip",
	}}
	store := missingStore()
	service := Service{Resolver: resolver, Fetcher: fetcher, Store: store}

	result, err := service.Acquire(context.Background(), Request{
		PURL:      testPURL,
		Integrity: requestIntegrity,
	}, Options{})
	if err != nil {
		t.Fatalf("Acquire() error = %v", err)
	}
	defer func() { _ = result.Body.Close() }()
	if result.Cached {
		t.Error("Cached = true, want false")
	}
	if !body.closed {
		t.Error("download body was not closed")
	}
	if result.Artifact.PURL != testPURL {
		t.Errorf("PURL = %q, want %q", result.Artifact.PURL, testPURL)
	}
	if result.Artifact.Filename != source.Filename {
		t.Errorf("Filename = %q, want %q", result.Artifact.Filename, source.Filename)
	}
	if result.Artifact.MediaType != fetcher.download.MediaType {
		t.Errorf("MediaType = %q, want %q", result.Artifact.MediaType, fetcher.download.MediaType)
	}
	if result.Artifact.Size != int64(len(content)) {
		t.Errorf("Size = %d, want %d", result.Artifact.Size, len(content))
	}
	wantDigest := sha256.Sum256(content)
	if result.Artifact.Digest != digest.Digest(fmt.Sprintf("sha256:%x", wantDigest)) {
		t.Errorf("Digest = %q, want sha256:%x", result.Artifact.Digest, wantDigest)
	}
	if got := readString(t, result.Body); got != string(content) {
		t.Errorf("Body = %q, want %q", got, content)
	}
	if store.stage == nil || !store.stage.committed {
		t.Fatal("stage was not committed")
	}
	if store.stage.discarded {
		t.Error("committed stage was discarded")
	}
	if got := store.stage.buffer.String(); got != string(content) {
		t.Errorf("staged bytes = %q, want %q", got, content)
	}
	if got := store.stage.request.Integrity; formatSRI(got) != formatSRI(requestIntegrity) {
		t.Errorf("staged integrity = %q, want %q", formatSRI(got), formatSRI(requestIntegrity))
	}
	if resolver.request.PURL != testPURL {
		t.Errorf("resolver PURL = %q, want %q", resolver.request.PURL, testPURL)
	}
}

func TestAcquireChecksResolvedStoreKeyBeforeFetching(t *testing.T) {
	content := []byte("stored resolved package")
	stored := testArtifact(t, testPURL, "selected.whl", content)
	store := &testStore{
		open: func(_ context.Context, request Request) (*Entry, error) {
			if request.Filename == "" {
				return nil, ErrNotFound
			}
			if request.Filename != stored.Filename {
				t.Errorf("filename = %q, want %q", request.Filename, stored.Filename)
			}
			return &Entry{Artifact: stored, Body: io.NopCloser(bytes.NewReader(content))}, nil
		},
	}
	resolver := &testResolver{source: Source{
		URL:      "https://files.example/selected.whl",
		Filename: stored.Filename,
	}}
	fetcher := &testFetcher{}
	service := Service{Resolver: resolver, Fetcher: fetcher, Store: store}

	result, err := service.Acquire(context.Background(), Request{PURL: testPURL}, Options{})
	if err != nil {
		t.Fatalf("Acquire() error = %v", err)
	}
	defer func() { _ = result.Body.Close() }()
	if !result.Cached {
		t.Error("Cached = false, want true")
	}
	if store.openCalls != 2 {
		t.Errorf("Open calls = %d, want 2", store.openCalls)
	}
	if fetcher.calls != 0 {
		t.Errorf("Fetch calls = %d, want zero", fetcher.calls)
	}
}

func TestAcquireFromUsesExactSourceWithoutResolver(t *testing.T) {
	content := []byte("exact source")
	store := missingStore()
	fetcher := &testFetcher{download: &Download{
		Body: io.NopCloser(bytes.NewReader(content)),
		Size: -1,
	}}
	resolver := &testResolver{err: errors.New("resolver must not be called")}
	service := Service{Resolver: resolver, Fetcher: fetcher, Store: store}

	result, err := service.AcquireFrom(context.Background(), Request{PURL: testPURL}, Source{
		URL:      "https://files.example/exact.tgz",
		Filename: "exact.tgz",
	}, Options{})
	if err != nil {
		t.Fatalf("AcquireFrom() error = %v", err)
	}
	defer func() { _ = result.Body.Close() }()
	if resolver.calls != 0 {
		t.Errorf("resolver calls = %d, want zero", resolver.calls)
	}
	if result.Artifact.Filename != "exact.tgz" {
		t.Errorf("Filename = %q, want exact.tgz", result.Artifact.Filename)
	}
}

func TestAcquireUsesSourceIntegrity(t *testing.T) {
	content := []byte("downloaded package")
	store := missingStore()
	service := Service{
		Resolver: &testResolver{source: Source{
			URL:       "https://registry.example/example.tgz",
			Filename:  "example.tgz",
			Integrity: testSRI(t, integrity.SHA512, []byte("different package")),
		}},
		Fetcher: &testFetcher{download: &Download{
			Body: io.NopCloser(bytes.NewReader(content)),
			Size: int64(len(content)),
		}},
		Store: store,
	}

	_, err := service.Acquire(context.Background(), Request{PURL: testPURL}, Options{})
	if err == nil || !strings.Contains(err.Error(), "integrity mismatch") {
		t.Fatalf("Acquire() error = %v, want integrity mismatch", err)
	}
	if store.stage == nil || !store.stage.discarded {
		t.Error("mismatched stage was not discarded")
	}
	if store.stage.committed {
		t.Error("mismatched stage was committed")
	}
}

func TestAcquireRejectsConflictingSourceFilename(t *testing.T) {
	store := missingStore()
	fetcher := &testFetcher{}
	service := Service{
		Resolver: &testResolver{source: Source{
			URL:      "https://registry.example/other.tgz",
			Filename: "other.tgz",
		}},
		Fetcher: fetcher,
		Store:   store,
	}

	_, err := service.Acquire(context.Background(), Request{
		PURL:     testPURL,
		Filename: "expected.tgz",
	}, Options{})
	if err == nil || !strings.Contains(err.Error(), "source filename") {
		t.Fatalf("Acquire() error = %v, want filename mismatch", err)
	}
	if fetcher.calls != 0 {
		t.Errorf("Fetch calls = %d, want zero", fetcher.calls)
	}
}

func TestAcquireRejectsDeclaredOversizeBeforeStaging(t *testing.T) {
	body := &trackingBody{Reader: strings.NewReader("large")}
	store := missingStore()
	service := Service{
		Resolver: &testResolver{source: Source{URL: "https://registry.example/large.tgz"}},
		Fetcher:  &testFetcher{download: &Download{Body: body, Size: 100}},
		Store:    store,
	}

	_, err := service.Acquire(context.Background(), Request{PURL: testPURL}, Options{MaxBytes: 10})
	if !errors.Is(err, ErrTooLarge) {
		t.Fatalf("Acquire() error = %v, want ErrTooLarge", err)
	}
	if store.stageCalls != 0 {
		t.Errorf("Stage calls = %d, want zero", store.stageCalls)
	}
	if !body.closed {
		t.Error("oversize download body was not closed")
	}
}

func TestAcquireClosesBodyWithInvalidDeclaredSize(t *testing.T) {
	body := &trackingBody{Reader: strings.NewReader("package")}
	store := missingStore()
	service := Service{
		Resolver: &testResolver{source: Source{URL: "https://registry.example/package.tgz"}},
		Fetcher:  &testFetcher{download: &Download{Body: body, Size: -2}},
		Store:    store,
	}

	_, err := service.Acquire(context.Background(), Request{PURL: testPURL}, Options{})
	if err == nil || !strings.Contains(err.Error(), "invalid size") {
		t.Fatalf("Acquire() error = %v, want invalid size", err)
	}
	if !body.closed {
		t.Error("invalid download body was not closed")
	}
	if store.stageCalls != 0 {
		t.Errorf("Stage calls = %d, want zero", store.stageCalls)
	}
}

func TestAcquireRejectsStreamingOversizeAndDiscards(t *testing.T) {
	content := []byte("more than five bytes")
	store := missingStore()
	service := Service{
		Resolver: &testResolver{source: Source{URL: "https://registry.example/large.tgz"}},
		Fetcher: &testFetcher{download: &Download{
			Body: io.NopCloser(bytes.NewReader(content)),
			Size: -1,
		}},
		Store: store,
	}

	_, err := service.Acquire(context.Background(), Request{PURL: testPURL}, Options{MaxBytes: 5})
	if !errors.Is(err, ErrTooLarge) {
		t.Fatalf("Acquire() error = %v, want ErrTooLarge", err)
	}
	if store.stage == nil || !store.stage.discarded {
		t.Error("oversize stage was not discarded")
	}
	if store.stage.buffer.Len() != 6 {
		t.Errorf("staged bytes = %d, want limit plus one", store.stage.buffer.Len())
	}
}

func TestAcquireAllowsMaximumSizeLimit(t *testing.T) {
	content := []byte("package")
	store := missingStore()
	service := Service{
		Resolver: &testResolver{source: Source{URL: "https://registry.example/package.tgz"}},
		Fetcher: &testFetcher{download: &Download{
			Body: io.NopCloser(bytes.NewReader(content)),
			Size: int64(len(content)),
		}},
		Store: store,
	}

	result, err := service.Acquire(context.Background(), Request{PURL: testPURL}, Options{MaxBytes: maxInt64})
	if err != nil {
		t.Fatal(err)
	}
	_ = result.Body.Close()
}

func TestAcquireDiscardsWhenCommitFails(t *testing.T) {
	store := missingStore()
	store.commitErr = errors.New("store unavailable")
	service := Service{
		Resolver: &testResolver{source: Source{URL: "https://registry.example/example.tgz"}},
		Fetcher: &testFetcher{download: &Download{
			Body: io.NopCloser(strings.NewReader("package")),
			Size: -1,
		}},
		Store: store,
	}

	_, err := service.Acquire(context.Background(), Request{PURL: testPURL}, Options{})
	if err == nil || !strings.Contains(err.Error(), "commit artifact") {
		t.Fatalf("Acquire() error = %v, want commit context", err)
	}
	if store.stage == nil || !store.stage.discarded {
		t.Error("failed commit stage was not discarded")
	}
}

func TestAcquireRejectsInvalidInputs(t *testing.T) {
	invalidIntegrity := integrity.SRI{{}}
	tests := []struct {
		name    string
		request Request
		options Options
		want    string
	}{
		{name: "invalid PURL", request: Request{PURL: "not-a-purl"}, want: "PURL"},
		{name: "unversioned PURL", request: Request{PURL: "pkg:npm/example"}, want: "no version"},
		{name: "PURL subpath", request: Request{PURL: testPURL + "#package.json"}, want: "subpath"},
		{name: "invalid integrity", request: Request{PURL: testPURL, Integrity: invalidIntegrity}, want: "integrity"},
		{name: "negative max bytes", request: Request{PURL: testPURL}, options: Options{MaxBytes: -1}, want: "max bytes"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := (Service{}).Acquire(context.Background(), test.request, test.options)
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("Acquire() error = %v, want %q", err, test.want)
			}
		})
	}
}

func TestAcquireClosesInvalidStoredEntry(t *testing.T) {
	body := &trackingBody{Reader: strings.NewReader("bad entry")}
	store := &testStore{
		open: func(context.Context, Request) (*Entry, error) {
			return &Entry{Artifact: artifacts.Artifact{}, Body: body}, nil
		},
	}

	_, err := (Service{Store: store}).Acquire(context.Background(), Request{PURL: testPURL}, Options{})
	if err == nil || !strings.Contains(err.Error(), "invalid metadata") {
		t.Fatalf("Acquire() error = %v, want invalid metadata", err)
	}
	if !body.closed {
		t.Error("invalid stored body was not closed")
	}
}

type testResolver struct {
	source  Source
	err     error
	calls   int
	request Request
}

func (resolver *testResolver) Resolve(_ context.Context, request Request) (Source, error) {
	resolver.calls++
	resolver.request = request
	return resolver.source, resolver.err
}

type testFetcher struct {
	download *Download
	err      error
	calls    int
	url      string
}

func (fetcher *testFetcher) Fetch(_ context.Context, url string) (*Download, error) {
	fetcher.calls++
	fetcher.url = url
	return fetcher.download, fetcher.err
}

type testStore struct {
	open       func(context.Context, Request) (*Entry, error)
	openCalls  int
	stageCalls int
	stage      *testStage
	stageErr   error
	commitErr  error
}

func (store *testStore) Open(ctx context.Context, request Request) (*Entry, error) {
	store.openCalls++
	return store.open(ctx, request)
}

//nolint:ireturn // Store requires the Stage interface so tests exercise the public boundary.
func (store *testStore) Stage(_ context.Context, request Request, source Source) (Stage, error) {
	store.stageCalls++
	if store.stageErr != nil {
		return nil, store.stageErr
	}
	store.stage = &testStage{request: request, source: source, commitErr: store.commitErr}
	return store.stage, nil
}

type testStage struct {
	request   Request
	source    Source
	buffer    bytes.Buffer
	artifact  artifacts.Artifact
	commitErr error
	committed bool
	discarded bool
}

func (stage *testStage) Write(content []byte) (int, error) {
	return stage.buffer.Write(content)
}

func (stage *testStage) Commit(_ context.Context, artifact artifacts.Artifact) (io.ReadCloser, error) {
	stage.artifact = artifact
	if stage.commitErr != nil {
		return nil, stage.commitErr
	}
	stage.committed = true
	return io.NopCloser(bytes.NewReader(stage.buffer.Bytes())), nil
}

func (stage *testStage) Discard(context.Context) error {
	stage.discarded = true
	return nil
}

type trackingBody struct {
	io.Reader
	closed bool
}

func (body *trackingBody) Close() error {
	body.closed = true
	return nil
}

func missingStore() *testStore {
	return &testStore{
		open: func(context.Context, Request) (*Entry, error) {
			return nil, ErrNotFound
		},
	}
}

func testArtifact(t *testing.T, packageURL, filename string, content []byte) artifacts.Artifact {
	t.Helper()
	sum := sha256.Sum256(content)
	artifact, err := artifacts.New(
		packageURL,
		digest.Digest(fmt.Sprintf("sha256:%x", sum)),
		int64(len(content)),
		filename,
		"application/octet-stream",
	)
	if err != nil {
		t.Fatal(err)
	}
	return artifact
}

func testSRI(t *testing.T, algorithm integrity.Algorithm, content []byte) integrity.SRI {
	t.Helper()
	var encoded string
	switch algorithm {
	case integrity.SHA256:
		sum := sha256.Sum256(content)
		encoded = fmt.Sprintf("%x", sum)
	case integrity.SHA384:
		sum := sha512.Sum384(content)
		encoded = fmt.Sprintf("%x", sum)
	case integrity.SHA512:
		sum := sha512.Sum512(content)
		encoded = fmt.Sprintf("%x", sum)
	default:
		t.Fatalf("unsupported test algorithm %s", algorithm)
	}
	digest, err := integrity.ParseHex(algorithm, encoded)
	if err != nil {
		t.Fatal(err)
	}
	return integrity.SRI{digest}
}

func formatSRI(metadata integrity.SRI) string {
	return integrity.FormatSRI(metadata)
}

func readString(t *testing.T, reader io.Reader) string {
	t.Helper()
	content, err := io.ReadAll(reader)
	if err != nil {
		t.Fatal(err)
	}
	return string(content)
}
