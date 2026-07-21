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

package v1

// Need to `go install github.com/pk910/dynamic-ssz/dynssz-gen@latest` for this to work.
//
// Note: SignedValidatorRegistrations is intentionally excluded from generation. It has a
// non-standard SSZ encoding (a bare list without a leading offset) required for conformance
// with https://ethereum.github.io/builder-specs/#/Builder/registerValidator, so its encoding
// file is hand-maintained. See the header of signedvalidatorregistrations_encoding.go.
//go:generate rm -f signedvalidatorregistration_encoding.go validatorregistration_encoding.go signedvalidatorregistrations_encoding.go
//nolint:revive
//go:generate dynssz-gen -package . -legacy -without-dynamic-expressions -types SignedValidatorRegistration:signedvalidatorregistration_encoding.go,ValidatorRegistration:validatorregistration_encoding.go,SignedValidatorRegistrations:signedvalidatorregistrations_encoding.go
