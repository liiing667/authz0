package scan

import (
	"bytes"
	"compress/gzip"
	"crypto/tls"
	"io"
	"io/ioutil"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/hahwul/authz0/pkg/models"
)

// maxBodySize caps how many response bytes are buffered as evidence.
const maxBodySize = 10 << 20 // 10 MiB

// Response is the captured evidence of a single probe. The status code,
// body and size are read exactly once and shared by every assertion and
// report field derived from this response.
type Response struct {
	StatusCode int
	Body       []byte
	Size       int
	Truncated  bool
}

func sendReq(req models.URL, args ScanArguments, template models.Template, headers []string) (*Response, error) {
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true,
			Renegotiation:      tls.RenegotiateOnceAsClient,
		},
		DisableKeepAlives: true,
		DialContext: (&net.Dialer{
			Timeout:   time.Duration(args.Timeout) * time.Second,
			DualStack: true,
		}).DialContext,
	}
	if args.ProxyAddress != "" {
		proxyAddress, err := url.Parse(args.ProxyAddress)
		if err != nil {

		}
		transport.Proxy = http.ProxyURL(proxyAddress)
	}
	client := &http.Client{
		Timeout:   time.Duration(args.Timeout) * time.Second,
		Transport: transport,
	}
	var r *http.Request
	if req.Body != "" {
		r, _ = http.NewRequest(req.Method, req.URL, bytes.NewBuffer([]byte(req.Body)))
	} else {
		r, _ = http.NewRequest(req.Method, req.URL, nil)
	}
	if req.ContentType == "json" {
		r.Header.Add("Content-Type", "application/json")
	} else {
		r.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	}

	if len(headers) > 0 {
		for _, v := range headers {
			h := strings.Split(v, ": ")
			if len(h) > 1 {
				r.Header.Add(h[0], h[1])
			}
		}
	}
	if args.Cookie != "" {
		r.Header.Add("Cookie", args.Cookie)
	}

	resp, err := client.Do(r)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var reader io.Reader = resp.Body
	if strings.EqualFold(resp.Header.Get("Content-Encoding"), "gzip") {
		gz, err := gzip.NewReader(resp.Body)
		if err != nil {
			return nil, err
		}
		defer gz.Close()
		reader = gz
	}
	body, err := ioutil.ReadAll(io.LimitReader(reader, maxBodySize+1))
	if err != nil {
		return nil, err
	}
	truncated := len(body) > maxBodySize
	if truncated {
		body = body[:maxBodySize]
	}
	return &Response{
		StatusCode: resp.StatusCode,
		Body:       body,
		Size:       len(body),
		Truncated:  truncated,
	}, nil
}
