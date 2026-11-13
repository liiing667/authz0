package scan

import (
	"bytes"
	"compress/gzip"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"testing"

	"github.com/hahwul/authz0/pkg/models"
	"gopkg.in/yaml.v2"
)

func testArgs() ScanArguments {
	return ScanArguments{Timeout: 5}
}

func TestCheckAssertFailRegexUsesCapturedBody(t *testing.T) {
	res := &Response{StatusCode: 200, Body: []byte("permission denied"), Size: 17}
	asserts := []models.Assert{{Type: "fail-regex", Value: "permission denied"}}
	if checkAssert(res, asserts) {
		t.Fatal("expected fail-regex match on captured body to fail the assert")
	}

	res = &Response{StatusCode: 200, Body: []byte("hello"), Size: 5}
	if !checkAssert(res, asserts) {
		t.Fatal("expected assert to pass when fail-regex does not match")
	}
}

func TestCheckAssertFailSizeUsesCapturedSize(t *testing.T) {
	asserts := []models.Assert{
		{Type: "fail-size", Value: "100"},
	}
	res := &Response{StatusCode: 200, Body: bytes.Repeat([]byte("a"), 100), Size: 100}
	if !checkAssert(res, asserts) {
		t.Fatal("expected assert to pass when size exactly matches fail-size")
	}
	res = &Response{StatusCode: 200, Body: []byte("hello"), Size: 5}
	if checkAssert(res, asserts) {
		t.Fatal("expected fail-size to fail the assert when size differs from fail-size")
	}
}

func TestCheckAssertTruncatedFailsExplicitly(t *testing.T) {
	res := &Response{StatusCode: 200, Body: []byte("hello"), Size: 5, Truncated: true}
	if checkAssert(res, nil) {
		t.Fatal("expected truncated response to fail the assert explicitly")
	}
}

func TestSendReqChunkedResponseMeasuresRealSize(t *testing.T) {
	payload := "chunked-body-without-content-length"
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, payload)
	}))
	defer server.Close()

	res, err := sendReq(models.URL{URL: server.URL, Method: "GET"}, testArgs(), models.Template{}, nil)
	if err != nil {
		t.Fatalf("sendReq error: %v", err)
	}
	if res.StatusCode != 200 {
		t.Fatalf("expected status 200, got %d", res.StatusCode)
	}
	if string(res.Body) != payload {
		t.Fatalf("expected body %q, got %q", payload, string(res.Body))
	}
	if res.Size != len(payload) {
		t.Fatalf("expected measured size %d, got %d", len(payload), res.Size)
	}
	if res.Truncated {
		t.Fatal("did not expect truncation for a small body")
	}
}

func TestSendReqGzipResponseIsDecodedOnce(t *testing.T) {
	payload := "gzipped secret token"
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Encoding", "gzip")
		gz := gzip.NewWriter(w)
		gz.Write([]byte(payload))
		gz.Close()
	}))
	defer server.Close()

	// Set Accept-Encoding explicitly so the transport does not transparently
	// decompress and the manual gzip path is exercised.
	headers := []string{"Accept-Encoding: gzip"}
	res, err := sendReq(models.URL{URL: server.URL, Method: "GET"}, testArgs(), models.Template{}, headers)
	if err != nil {
		t.Fatalf("sendReq error: %v", err)
	}
	if string(res.Body) != payload {
		t.Fatalf("expected decoded body %q, got %q", payload, string(res.Body))
	}
	if res.Size != len(payload) {
		t.Fatalf("expected measured size %d, got %d", len(payload), res.Size)
	}

	asserts := []models.Assert{{Type: "fail-regex", Value: "secret token"}}
	if checkAssert(res, asserts) {
		t.Fatal("expected fail-regex to match the decoded gzip body")
	}
}

func TestRunProducesStableOrderedResults(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/denied":
			w.WriteHeader(http.StatusForbidden)
			fmt.Fprint(w, "permission denied")
		default:
			w.WriteHeader(http.StatusOK)
			fmt.Fprint(w, "hello")
		}
	}))
	defer server.Close()

	template := models.Template{
		Name: "test",
		URLs: []models.URL{
			{URL: server.URL + "/ok", Method: "GET", AllowRole: []string{"user"}},
			{URL: server.URL + "/denied", Method: "GET", AllowRole: []string{"user"}},
		},
		Asserts: []models.Assert{{Type: "fail-regex", Value: "permission denied"}},
		Credentials: []models.Credential{
			{Rolename: "user", Headers: []string{}},
		},
	}
	data, err := yaml.Marshal(&template)
	if err != nil {
		t.Fatalf("marshal template: %v", err)
	}
	filename := filepath.Join(t.TempDir(), "template.yaml")
	if err := os.WriteFile(filename, data, 0644); err != nil {
		t.Fatalf("write template: %v", err)
	}

	args := testArgs()
	args.Concurrency = 4
	results := Run(filename, args, false)

	if len(results) != 2 {
		t.Fatalf("expected 2 results, got %d", len(results))
	}
	for i, result := range results {
		wantIndex := "#" + strconv.Itoa(i)
		if result.Index != wantIndex {
			t.Fatalf("expected stable index %s at slot %d, got %s", wantIndex, i, result.Index)
		}
	}
	if results[0].URL != server.URL+"/ok" || results[0].Result != "O" {
		t.Fatalf("expected first result to pass for /ok, got %+v", results[0])
	}
	if results[1].URL != server.URL+"/denied" || results[1].Result != "X" {
		t.Fatalf("expected second result to flag /denied, got %+v", results[1])
	}
	if results[1].RespSize != len("permission denied") {
		t.Fatalf("expected measured size %d, got %d", len("permission denied"), results[1].RespSize)
	}
}
