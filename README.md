# artifacts

Describe completed package files with canonical package coordinates, an OCI-compatible content digest, and a byte count. Optional filename and media type labels stay attached to the value without being treated as paths or detected content.

## Install

```bash
go get github.com/git-pkgs/artifacts
```

## Construction

Use `New` after a package file has been read and hashed:

```go
artifact, err := artifacts.New(
	"pkg:npm/lodash@4.17.21",
	digest.Digest("sha256:9e15e8133c3c58e28e70fb5b3f62f74c2fb542f4391fb4128a4d5656d57e7606"),
	318961,
	"lodash-4.17.21.tgz",
	"application/gzip",
)
```

`New` parses the package URL and stores its canonical form. It accepts package URL qualifiers and subpaths. SHA-256, SHA-384, and SHA-512 digests use the OCI form `algorithm:hex`.

The digest identifies the bytes. The package URL, filename, and media type describe how those bytes are used, so two artifacts may share a digest while carrying different package metadata.

## Validation

Call `Validate` on values received from another component:

```go
artifact := artifacts.Artifact{
	PURL:      "pkg:pypi/charset-normalizer@3.3.2",
	Digest:    digest.Digest("sha256:f30c3d80b4c84420e54e1b5f80e5d1db6f39ccf62f5c2b9ea308c67c9cb4f4c1"),
	Size:      142373,
	Filename:  "charset_normalizer-3.3.2-py3-none-any.whl",
	MediaType: "application/zip",
}
if err := artifact.Validate(); err != nil {
	return err
}
```

Validation rejects malformed package URLs, unavailable or malformed digest algorithms, and negative sizes. Filename and media type are optional labels. Download URLs, storage paths, hashing, MIME detection, and policy belong to callers.

## Development

Run tests, benchmarks, fuzzing, and static checks:

```bash
make test
make bench
make fuzz
make lint
```

## License

MIT
