// Copyright The Notary Project Authors.
// Licensed under the Apache License, Version 2.0.

package erofs

import (
	"bytes"
	"context"
	"os/exec"
	"testing"
)

func TestCalculateArtifactMatchesRootHash(t *testing.T) {
	if _, err := exec.LookPath("veritysetup"); err != nil {
		t.Skip("veritysetup is not installed")
	}

	data := bytes.Repeat([]byte{0x5a}, 4096)
	opts := DefaultVeritysetupOptions()
	opts.UUID = "1f8a14d8-0cc8-5d31-81ed-ea292a3f0cf2"

	calculator := NewVerityCalculator(t.TempDir())
	rootHash, err := calculator.CalculateRootHash(context.Background(), data, &opts)
	if err != nil {
		t.Fatal(err)
	}
	artifact, err := calculator.CalculateArtifact(context.Background(), data, &opts)
	if err != nil {
		t.Fatal(err)
	}

	if artifact.RootHash != rootHash {
		t.Fatalf("artifact root hash = %s, combined-device root hash = %s", artifact.RootHash, rootHash)
	}
	if len(artifact.HashTree) == 0 {
		t.Fatal("hash tree is empty")
	}
	if artifact.DataSize != uint64(len(data)) {
		t.Fatalf("data size = %d, want %d", artifact.DataSize, len(data))
	}
}
