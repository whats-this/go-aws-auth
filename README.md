# Go S3 Signature v2 Helper
[![GoDoc](https://godoc.org/github.com/whats-this/go-s3-sig-v2?status.svg)](https://godoc.org/github.com/whats-this/go-s3-sig-v2)

Go-S3-Sig-v2 is a fast and lightweight library for creating requests that
implement
[AWS' S3 v2 signature specification](https://docs.aws.amazon.com/AmazonS3/latest/dev/RESTAuthentication.html),
which is particularly useful for S3-compatible object storage systems like
[Pithos](https://github.com/exoscale/pithos) that don't support AWS v4
signatures. It is a fork of
[smartystreets/go-aws-auth](https://github.com/smartystreets/go-aws-auth) with
all other signature types removed (as they are in `aws-sdk-go` and aren't
needed for `whats-this`) and some performance improvements.

This wouldn't be a thing if [aws-sdk-go](https://github.com/aws/aws-sdk-go) had
it implemented to begin with.

# Using
`go get` it:

	$ go get github.com/whats-this/go-s3-sig-v2

Then use it:

	import "github.com/whats-this/go-s3-sig-v2"

	credentials := s3sigv2.S3CredentialsPair{
		AccessKeyID:     "",
		SecretAccessKey: ""
	}
	credentials.SignHTTPRequest(req)

The library does not check environment variables or anywhere else for
credentials, it is up to you to manage where the credentials come from and
expiration stuff.

Remember to be careful hard-coding credentials into your application if the code
is committed to source control.

### Contributing
You are more than welcome to contribute. If you are wanting to make a breaking
change, please open an issue first to discuss it. Please ensure any tests pass
with your contributions.

### License
A copy of the MIT license can be found in `LICENSE`.
