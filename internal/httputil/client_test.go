// Copyright The Notary Project Authors.
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package httputil

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"oras.land/oras-go/v2/registry/remote/retry"
)

func TestNewAuthClient(t *testing.T) {
	t.Run("nil client", func(t *testing.T) {
		client := NewAuthClient(context.Background(), nil)
		if client == nil {
			t.Fatal("expected non-nil auth client")
		}
		if client.Cache == nil {
			t.Fatal("expected non-nil cache")
		}
	})

	t.Run("custom client", func(t *testing.T) {
		httpClient := &http.Client{}
		client := NewAuthClient(context.Background(), httpClient)
		if client == nil {
			t.Fatal("expected non-nil auth client")
		}
	})
}

func TestNewClient(t *testing.T) {
	t.Run("nil client", func(t *testing.T) {
		client := NewClient(context.Background(), nil)
		if client == nil {
			t.Fatal("expected non-nil client")
		}
	})

	t.Run("custom client", func(t *testing.T) {
		httpClient := &http.Client{}
		client := NewClient(context.Background(), httpClient)
		if client == nil {
			t.Fatal("expected non-nil client")
		}
	})
}

func TestWithRetry(t *testing.T) {
	t.Run("nil client gets default transport", func(t *testing.T) {
		client := withRetry(nil)
		if client == nil {
			t.Fatal("expected non-nil client")
		}
		rt, ok := client.Transport.(*retry.Transport)
		if !ok {
			t.Fatalf("expected *retry.Transport, got %T", client.Transport)
		}
		if rt.Base != http.DefaultTransport {
			t.Fatal("expected base to be http.DefaultTransport")
		}
	})

	t.Run("client with nil transport gets default transport", func(t *testing.T) {
		client := withRetry(&http.Client{})
		rt, ok := client.Transport.(*retry.Transport)
		if !ok {
			t.Fatalf("expected *retry.Transport, got %T", client.Transport)
		}
		if rt.Base != http.DefaultTransport {
			t.Fatal("expected base to be http.DefaultTransport")
		}
	})

	t.Run("custom transport is preserved", func(t *testing.T) {
		custom := &http.Transport{}
		client := withRetry(&http.Client{Transport: custom})
		rt, ok := client.Transport.(*retry.Transport)
		if !ok {
			t.Fatalf("expected *retry.Transport, got %T", client.Transport)
		}
		if rt.Base != custom {
			t.Fatal("expected base to be the custom transport")
		}
	})
}

func TestRetryOnServerError(t *testing.T) {
	var attempts atomic.Int32
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if attempts.Add(1) == 1 {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	client := NewClient(context.Background(), nil)
	resp, err := client.Get(ts.URL)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected status 200, got %d", resp.StatusCode)
	}
	if got := attempts.Load(); got != 2 {
		t.Fatalf("expected 2 attempts, got %d", got)
	}
}

func TestNoRetryOnClientError(t *testing.T) {
	var attempts atomic.Int32
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		attempts.Add(1)
		w.WriteHeader(http.StatusBadRequest)
	}))
	defer ts.Close()

	client := NewClient(context.Background(), nil)
	resp, err := client.Get(ts.URL)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("expected status 400, got %d", resp.StatusCode)
	}
	if got := attempts.Load(); got != 1 {
		t.Fatalf("expected 1 attempt (no retry), got %d", got)
	}
}

func TestSetUserAgent(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ua := r.Header.Get("User-Agent")
		if ua != userAgent {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	client := NewClient(context.Background(), nil)
	resp, err := client.Get(ts.URL)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected status 200, got %d", resp.StatusCode)
	}
}
