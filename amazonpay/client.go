package amazonpay

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"runtime"
	"time"

	"github.com/mukezhz/aws-services-go/amazonpay/signing"

	"github.com/rs/xid"
)

const (
	SDKVersion = "2.2.1"
)

const (
	APIVersion = "v2"
)

var (
	RegionMap = map[string]string{
		"eu": "eu",
		"de": "eu",
		"uk": "eu",
		"us": "na",
		"na": "na",
		"jp": "jp",
	}
	RegionHostMap = map[string]string{
		"eu": "pay-api.amazon.eu",
		"na": "pay-api.amazon.com",
		"jp": "pay-api.amazon.jp",
	}
)

// Client type
type Client struct {
	PublicKeyID string
	PrivateKey  []byte
	Region      string
	Sandbox     bool
	HTTPClient  *http.Client
	Algorithm   string
	salt        int
	endpoint    *url.URL
}

type ClientInput struct {
	PublicKeyID string
	PrivateKey  []byte
	Region      string
	Sandbox     bool
	HTTPClient  *http.Client
	Version     string
}

// New returns a new pay client instance.
func New(input ClientInput) (*Client, error) {
	c := &Client{
		PublicKeyID: input.PublicKeyID,
		PrivateKey:  input.PrivateKey,
		Region:      input.Region,
		Sandbox:     input.Sandbox,
		HTTPClient:  input.HTTPClient,
	}
	endpointURL := c.createEndpointURL()
	u, err := url.Parse(endpointURL)
	if err != nil {
		return nil, err
	}
	c.endpoint = u
	version := input.Version
	if input.Version != "v1" {
		version = "v2"
	}
	al := signing.GetAlgorithm(version)
	c.Algorithm = al.Algorithm
	c.salt = al.SaltLength
	return c, nil
}

func (c *Client) createEndpointURL() string {
	modePath := "live"
	if c.Sandbox {
		modePath = "sandbox"
	}
	host := RegionHostMap[RegionMap[c.Region]]
	return "https://" + host + "/" + modePath + "/"
}

// NewRequest method
func (c *Client) NewRequest(method, path string, body interface{}) (*http.Request, error) {
	u, err := c.endpoint.Parse(path)
	if err != nil {
		return nil, err
	}

	var reqBody io.ReadWriter
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return nil, err
		}
		reqBody = bytes.NewBuffer(b)
	}

	req, err := http.NewRequest(method, u.String(), reqBody)
	if err != nil {
		return nil, err
	}

	if method == http.MethodPost {
		req.Header.Set("x-amz-pay-idempotency-key", xid.New().String())
	}
	req.Header.Set("x-amz-pay-region", RegionMap[c.Region])
	req.Header.Set("x-amz-pay-host", RegionHostMap[RegionMap[c.Region]])
	req.Header.Set("x-amz-pay-date", time.Now().UTC().Format("20060102T150405Z"))
	req.Header.Set("content-type", "application/json")
	req.Header.Set("accept", "application/json")
	req.Header.Set("user-agent", fmt.Sprintf("amazon-pay-api-sdk-go/%s (GO/%s)", SDKVersion, runtime.Version()))

	canonicalRequest, err := signing.CanonicalRequest(req)
	if err != nil {
		return nil, err
	}
	stringToSign, err := signing.StringToSign(canonicalRequest, c.Algorithm)
	if err != nil {
		return nil, err
	}
	signature, err := signing.Sign(c.PrivateKey, stringToSign, c.salt)
	if err != nil {
		return nil, err
	}
	signedHeaders := signing.SignedHeaders(req)
	authValue := signing.AuthHeaderValue(c.PublicKeyID, signedHeaders, signature, c.Algorithm)
	req.Header.Set("Authorization", authValue)

	return req, nil
}

// Do method
func (c *Client) Do(ctx context.Context, req *http.Request, v interface{}) (*http.Response, error) {
	resp, err := c.HTTPClient.Do(req.WithContext(ctx))
	if err != nil {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		default:
		}
		return nil, err
	}

	defer resp.Body.Close()

	if v != nil {
		if w, ok := v.(io.Writer); ok {
			_, err := io.Copy(w, resp.Body)
			if err != nil {
				return nil, err
			}
		} else {
			if err := json.NewDecoder(resp.Body).Decode(v); err != nil {
				return resp, err
			}
		}
	}
	return resp, nil
}
