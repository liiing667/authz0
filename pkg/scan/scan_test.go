package scan

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"github.com/hahwul/authz0/pkg/models"
	"gopkg.in/yaml.v2"
)

func writeTemplate(t *testing.T, template models.Template) string {
	t.Helper()
	data, err := yaml.Marshal(&template)
	if err != nil {
		t.Fatalf("marshal template: %v", err)
	}
	path := filepath.Join(t.TempDir(), "template.yaml")
	if err := os.WriteFile(path, data, 0644); err != nil {
		t.Fatalf("write template: %v", err)
	}
	return path
}

func TestRunDeterministicOrderWithConcurrency(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(time.Millisecond)
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	var urls []models.URL
	for i := 0; i < 24; i++ {
		urls = append(urls, models.URL{
			URL:    fmt.Sprintf("%s/path-%d", server.URL, i),
			Method: "GET",
			Alias:  fmt.Sprintf("alias-%d", i),
		})
	}
	template := models.Template{
		Name: "determinism",
		URLs: urls,
		Credentials: []models.Credential{
			{Rolename: "admin"},
			{Rolename: "user"},
			{Rolename: "guest"},
		},
	}
	path := writeTemplate(t, template)
	args := ScanArguments{Concurrency: 8, Timeout: 5}

	first := Run(path, args, false)
	if len(first) != len(urls)*len(template.Credentials) {
		t.Fatalf("expected %d results, got %d", len(urls)*len(template.Credentials), len(first))
	}

	// Results must follow template URL order, then role declaration order.
	for i, u := range urls {
		for j, cred := range template.Credentials {
			r := first[i*len(template.Credentials)+j]
			if r.URL != u.URL || r.RoleName != cred.Rolename {
				t.Errorf("result[%d] = (%s, %s), want (%s, %s)",
					i*len(template.Credentials)+j, r.URL, r.RoleName, u.URL, cred.Rolename)
			}
			if r.Index != fmt.Sprintf("#%d", i) {
				t.Errorf("result[%d].Index = %s, want #%d", i*len(template.Credentials)+j, r.Index, i)
			}
		}
	}

	for run := 0; run < 5; run++ {
		got := Run(path, args, false)
		if !reflect.DeepEqual(first, got) {
			t.Fatalf("run %d drifted from first run", run)
		}
	}

	// JSON output must contain every entry.
	data, err := json.Marshal(&first)
	if err != nil {
		t.Fatalf("marshal results: %v", err)
	}
	var decoded []models.Result
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("unmarshal results: %v", err)
	}
	if len(decoded) != len(first) {
		t.Fatalf("json has %d entries, want %d", len(decoded), len(first))
	}
	for _, u := range urls {
		if !containsURL(decoded, u.URL) {
			t.Fatalf("json missing entry for %s", u.URL)
		}
	}
}

func containsURL(results []models.Result, url string) bool {
	for _, r := range results {
		if r.URL == url {
			return true
		}
	}
	return false
}

func TestRunMismatchCategorization(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/forbidden" {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	template := models.Template{
		Name: "categorization",
		URLs: []models.URL{
			{URL: server.URL + "/ok", Method: "GET", DenyRole: []string{"user"}},
			{URL: server.URL + "/forbidden", Method: "GET", AllowRole: []string{"admin"}},
			{URL: server.URL + "/ok", Method: "GET", AllowRole: []string{"admin"}},
		},
		Credentials: []models.Credential{
			{Rolename: "admin"},
			{Rolename: "user"},
		},
	}
	path := writeTemplate(t, template)
	results := Run(path, ScanArguments{Concurrency: 8, Timeout: 5}, false)

	type expectation struct {
		result       string
		mismatchType string
	}
	expected := []expectation{
		// /ok denyRole=[user]
		{result: "O", mismatchType: models.MismatchNone},
		{result: "X", mismatchType: models.MismatchOverPrivilege},
		// /forbidden allowRole=[admin]
		{result: "X", mismatchType: models.MismatchUnderPrivilege},
		{result: "O", mismatchType: models.MismatchNone},
		// /ok allowRole=[admin]
		{result: "O", mismatchType: models.MismatchNone},
		{result: "X", mismatchType: models.MismatchOverPrivilege},
	}
	if len(results) != len(expected) {
		t.Fatalf("expected %d results, got %d", len(expected), len(results))
	}
	for i, want := range expected {
		if results[i].Result != want.result {
			t.Errorf("results[%d] (%s as %s).Result = %q, want %q",
				i, results[i].URL, results[i].RoleName, results[i].Result, want.result)
		}
		if results[i].MismatchType != want.mismatchType {
			t.Errorf("results[%d] (%s as %s).MismatchType = %q, want %q",
				i, results[i].URL, results[i].RoleName, results[i].MismatchType, want.mismatchType)
		}
		if results[i].Error != "" {
			t.Errorf("results[%d].Error = %q, want empty", i, results[i].Error)
		}
	}
}

func TestRunRequestFailureRecordedSeparately(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	deadURL := server.URL
	server.Close()

	template := models.Template{
		Name: "request-failure",
		URLs: []models.URL{
			{URL: deadURL + "/unreachable", Method: "GET", AllowRole: []string{"admin"}},
		},
		Credentials: []models.Credential{
			{Rolename: "admin"},
		},
	}
	path := writeTemplate(t, template)
	results := Run(path, ScanArguments{Concurrency: 8, Timeout: 2}, false)

	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}
	r := results[0]
	if r.Error == "" {
		t.Error("expected request error to be recorded in Result.Error")
	}
	if r.Result != "X" {
		t.Errorf("Result = %q, want X", r.Result)
	}
	if r.MismatchType != models.MismatchNone {
		t.Errorf("MismatchType = %q, want empty for request failures", r.MismatchType)
	}
	if r.Assert {
		t.Error("Assert = true, want false for request failures")
	}
}

func TestRunAssertFailureWithoutRole(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	}))
	defer server.Close()

	template := models.Template{
		Name: "assert-failure",
		URLs: []models.URL{
			{URL: server.URL + "/forbidden", Method: "GET"},
		},
		Credentials: []models.Credential{
			{Rolename: ""},
		},
	}
	path := writeTemplate(t, template)
	results := Run(path, ScanArguments{Concurrency: 1, Timeout: 5}, false)

	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}
	r := results[0]
	if r.Assert {
		t.Error("Assert = true, want false")
	}
	if r.Result != "O" {
		t.Errorf("Result = %q, want O (no role policy to violate)", r.Result)
	}
	if r.Error != "" {
		t.Errorf("Error = %q, want empty", r.Error)
	}
}

func TestRunSingleRoleMode(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Test") != "yes" {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	template := models.Template{
		Name: "single-role",
		URLs: []models.URL{
			{URL: server.URL + "/ok", Method: "GET", AllowRole: []string{"tester"}},
		},
	}
	path := writeTemplate(t, template)
	args := ScanArguments{
		RoleName:    "tester",
		Headers:     []string{"X-Test: yes"},
		Concurrency: 4,
		Timeout:     5,
	}
	results := Run(path, args, false)

	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}
	r := results[0]
	if r.RoleName != "tester" {
		t.Errorf("RoleName = %q, want tester", r.RoleName)
	}
	if r.Result != "O" || !r.Assert || !r.AssertAllowRole {
		t.Errorf("unexpected result: %+v", r)
	}
}
