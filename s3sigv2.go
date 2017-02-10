// Package s3sigv2 implements AWS S3 request signing using Signature Version 2,
// documentation on the signature structure can be found at
// http://docs.aws.amazon.com/AmazonS3/latest/dev/RESTAuthentication.html.
package s3sigv2

import (
	"crypto/hmac"
	"crypto/sha1"
	"hash"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go/aws/request"
)

const (
	s3TimeFormat   = time.RFC1123Z
	s3Subresources = "acl,lifecycle,location,logging,notification,partNumber,policy,requestPayment,torrent,uploadId,uploads,versionId,versioning,versions,website"
)

var subresourcesArray []string

// S3CredentialPair stores the information necessary to authenticate against the
// S3-compatible API and provides methods to create signatures and/or attach
// them to requests.
type S3CredentialPair struct {
	AccessKeyID     string
	SecretAccessKey string
	SecurityToken   string `json:"Token"`
	hmacSHA1        hash.Hash
}

// GetSignatureBytes returns the raw bytes of the generated request signature
// (not entire auth header). This will insert a `Date` header into the request
// if it doesn't exist, as S3 signatures require a valid `Date` or `x-amz-date`
// header.
func (c *S3CredentialPair) GetSignatureBytes(req *http.Request) []byte {
	prepareRequest(req)
	return c.SignBytesHmacSHA1([]byte(stringToSign(req)))
}

// SignHTTPRequest signs a request by adding missing headers and constructing a
// string to use for the `Authorization` request header.
func (c *S3CredentialPair) SignHTTPRequest(req *http.Request) *http.Request {
	prepareRequest(req)
	signature := string(c.SignBytesHmacSHA1([]byte(stringToSign(req))))
	authHeader := "AWS:" + c.AccessKeyID + ":" + signature
	req.Header.Set("Authorization", authHeader)
	return req
}

// SignSDKRequest signs a request by adding missing headers and constructing a
// string to use for the `Authorization` request header. This is just a
// shorthand for
// `s3CredentialsPair.SignHTTPRequest(request.Request.HTTPRequest)`.
func (c *S3CredentialPair) SignSDKRequest(req *request.Request) *http.Request {
	return c.SignHTTPRequest(req.HTTPRequest)
}

// SignBytesHmacSHA1 signs a []byte using the SecretAccessKey and returns it.
func (c *S3CredentialPair) SignBytesHmacSHA1(content []byte) []byte {
	if c.hmacSHA1 == nil {
		c.hmacSHA1 = hmac.New(sha1.New, []byte(c.SecretAccessKey))
	}
	c.hmacSHA1.Write(content)
	hash := c.hmacSHA1.Sum(nil)
	c.hmacSHA1.Reset()
	return hash
}

// stringToSign generates a raw string that will later be signed using HMAC-SHA1
// so that the request destination can verify the request using the secret key.
// Refer to Amazon's documentation on the signature specification at
// http://docs.aws.amazon.com/AmazonS3/latest/dev/RESTAuthentication.html#ConstructingTheAuthenticationHeader
// for more information.
func stringToSign(req *http.Request) string {
	str := req.Method + "\n"
	// The signature specification only requires MD5 in stringToSign when
	// the Content-MD5 header is present. http.Header.Get() will return an
	// empty string when there are no values for that header in the header
	// map.
	str += req.Header.Get("Content-MD5") + "\n"
	str += req.Header.Get("Content-Type") + "\n"
	str += req.Header.Get("Date") + "\n"
	if canonicalHeaders := canonicalAmzHeaders(req); canonicalHeaders != "" {
		str += canonicalHeaders
	}
	str += canonicalResource(req)
	return str
}

// canonicalAmzHeaders generates a string from a HTTP request of x-amz headers
// and their values in order with comma-separated values. Refer to Amazon's
// documentation on the signature specification at
// http://docs.aws.amazon.com/AmazonS3/latest/dev/RESTAuthentication.html#RESTAuthenticationConstructingCanonicalizedAmzHeaders
// for more information.
func canonicalAmzHeaders(req *http.Request) string {
	var headers []string
	for header := range req.Header {
		standardized := strings.ToLower(strings.TrimSpace(header))
		if strings.HasPrefix(standardized, "x-amz") {
			headers = append(headers, standardized)
		}
	}
	sort.Strings(headers)

	for i, header := range headers {
		headers[i] = header + ":" + strings.Replace(req.Header.Get(header), "\n", " ", -1)
	}

	if len(headers) > 0 {
		return strings.Join(headers, "\n") + "\n"
	}
	return ""
}

// canonicalResource generates an S3 "canonical resource" Refer to Amazon's
// documentation on the signature specification at
// http://docs.aws.amazon.com/AmazonS3/latest/dev/RESTAuthentication.html#ConstructingTheCanonicalizedResourceElement
// for more information
func canonicalResource(req *http.Request) string {
	resource := ""

	// TODO: use a more reliable method to determine virtual hosts
	if strings.Count(req.Host, ".") == 3 {
		bucketname := strings.Split(req.Host, ".")[0]
		resource += "/" + bucketname
	}
	resource += req.URL.Path

	if subresourcesArray == nil {
		subresourcesArray = strings.Split(s3Subresources, ",")
	}
	for _, subres := range subresourcesArray {
		if strings.HasPrefix(req.URL.RawQuery, subres) {
			resource += "?" + subres
		}
	}
	return resource
}

// prepareRequest inserts a `Date` header into the request, inserts a security
// token header into the request if supplied, and normalizes the request path if
// it is empty.
func prepareRequest(req *http.Request, token ...string) {
	req.Header.Set("Date", time.Now().Format(s3TimeFormat))
	if len(token) > 0 && len(token[0]) > 0 {
		req.Header.Set("X-Amz-Security-Token", token[0])
	}
	if req.URL.Path == "" {
		req.URL.Path += "/"
	}
}
