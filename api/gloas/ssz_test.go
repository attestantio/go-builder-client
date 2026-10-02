// Copyright © 2026 Attestant Limited.
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package gloas_test

import (
	"crypto/sha256"
	"encoding/hex"
	"testing"

	"github.com/attestantio/go-builder-client/api/gloas"
	"github.com/attestantio/go-eth2-client/spec/phase0"
	"github.com/stretchr/testify/require"
)

type sszType interface {
	MarshalSSZ() ([]byte, error)
	UnmarshalSSZ([]byte) error
	HashTreeRoot() ([32]byte, error)
}

func assertSSZGolden(t *testing.T, obj sszType, fresh sszType, wantSize int, wantSHA, wantRoot string) {
	t.Helper()

	enc, err := obj.MarshalSSZ()
	require.NoError(t, err)
	require.Equal(t, wantSize, len(enc), "encoded size")

	sum := sha256.Sum256(enc)
	require.Equal(t, wantSHA, hex.EncodeToString(sum[:]), "sha256 of encoding")

	require.NoError(t, fresh.UnmarshalSSZ(enc))
	reenc, err := fresh.MarshalSSZ()
	require.NoError(t, err)
	require.Equal(t, enc, reenc, "round-trip encoding")

	root, err := obj.HashTreeRoot()
	require.NoError(t, err)
	require.Equal(t, wantRoot, hex.EncodeToString(root[:]), "hash tree root")
}

func fill(b []byte, v byte) {
	for i := range b {
		b[i] = v
	}
}
func sig(v byte) phase0.BLSSignature { var s phase0.BLSSignature; fill(s[:], v); return s }

func builderRequestAuth() *gloas.BuilderRequestAuth {
	return &gloas.BuilderRequestAuth{
		Data: []byte("builder.example.com"),
		Slot: 12345,
	}
}

func signedBuilderRequestAuth() *gloas.SignedBuilderRequestAuth {
	return &gloas.SignedBuilderRequestAuth{
		Message:   builderRequestAuth(),
		Signature: sig(0x88),
	}
}

func builderPreferences() *gloas.BuilderPreferences {
	return &gloas.BuilderPreferences{
		MaxExecutionPayment: 1000000000,
	}
}

func TestBuilderRequestAuthGoldenSSZ(t *testing.T) {
	assertSSZGolden(t, builderRequestAuth(), new(gloas.BuilderRequestAuth),
		31,
		"0c46ddaa68cab0d5f572ea20bd39cb6ebeb169c5efe6780a0ba4738f6b05e0d6",
		"6ad33c944510322cf6c8f8148a2e60a5b199367c6ef7ab4f0a98133f9c9fd6c9",
	)
}

func TestSignedBuilderRequestAuthGoldenSSZ(t *testing.T) {
	assertSSZGolden(t, signedBuilderRequestAuth(), new(gloas.SignedBuilderRequestAuth),
		131,
		"4dc832aff26ce7e29aa8673d3ff50b30f8e3980b65a8d16b066e13bb12f8d253",
		"d290c9541a047e45e9becf0f2b69d2e19f451353ce626c5f74690c1f63ef30af",
	)
}

func TestBuilderPreferencesGoldenSSZ(t *testing.T) {
	assertSSZGolden(t, builderPreferences(), new(gloas.BuilderPreferences),
		8,
		"e6de5d37fa002cfb13cf9e064305afe68e4cba155fe4b7233673d46220272f03",
		"00ca9a3b00000000000000000000000000000000000000000000000000000000",
	)
}

func TestBuilderPreferencesRequestGoldenSSZ(t *testing.T) {
	obj := &gloas.BuilderPreferencesRequest{
		Preferences: builderPreferences(),
		Auth:        signedBuilderRequestAuth(),
	}
	assertSSZGolden(t, obj, new(gloas.BuilderPreferencesRequest),
		143,
		"c3dc9de1d0cf2f8ed00c4071342813a782832b4791301e64ddec2c32d8b39e0a",
		"0570d3af3dc03839eabdf73cddfbf12eb3d65caa758fb8a003be919c719d0a6c",
	)
}

func TestBuilderRequestAuthSSZMaxData(t *testing.T) {
	obj := &gloas.BuilderRequestAuth{Data: make([]byte, gloas.MaxBuilderAuthDataSize), Slot: 1}
	enc, err := obj.MarshalSSZ()
	require.NoError(t, err)
	require.Equal(t, 12+gloas.MaxBuilderAuthDataSize, len(enc))
	require.NoError(t, new(gloas.BuilderRequestAuth).UnmarshalSSZ(enc))

	tooLong := &gloas.BuilderRequestAuth{Data: make([]byte, gloas.MaxBuilderAuthDataSize+1), Slot: 1}
	if enc, err = tooLong.MarshalSSZ(); err == nil {
		require.Error(t, new(gloas.BuilderRequestAuth).UnmarshalSSZ(enc))
	}
}
