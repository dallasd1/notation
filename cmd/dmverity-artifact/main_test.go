// Copyright The Notary Project Authors.
// Licensed under the Apache License, Version 2.0.

package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRunRejectsLayerDigestMismatch(t *testing.T) {
	input := filepath.Join(t.TempDir(), "layer.tar.gz")
	if err := os.WriteFile(input, []byte("not the expected blob"), 0644); err != nil {
		t.Fatal(err)
	}

	err := run(
		"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		input,
		t.TempDir(),
	)
	if err == nil || !strings.Contains(err.Error(), "layer digest mismatch") {
		t.Fatalf("run() error = %v, want layer digest mismatch", err)
	}
}

func TestRunRequiresPaths(t *testing.T) {
	if err := run("sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "", "out"); err == nil {
		t.Fatal("run() with no input succeeded")
	}
	if err := run("sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "input", ""); err == nil {
		t.Fatal("run() with no output directory succeeded")
	}
}
