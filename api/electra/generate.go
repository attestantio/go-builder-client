// Copyright © 2024 Attestant Limited.
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

package electra

//nolint:revive
// Need to `go install github.com/ferranbt/fastssz/sszgen@latest` for this to work.
//go:generate rm -f builderbid_ssz.go signedbuilderbid_ssz.go submitblockrequest_ssz.go
//go:generate sszgen --suffix ssz --include ../../../go-eth2-client/spec/electra,../../../go-eth2-client/spec/deneb,../../../go-eth2-client/spec/capella,../../../go-eth2-client/spec/bellatrix,../../../go-eth2-client/spec/phase0,../v1,../deneb --path . --objs BuilderBid,SignedBuilderBid,SubmitBlockRequest
//go:generate goimports -w builderbid_ssz.go signedbuilderbid_ssz.go submitblockrequest_ssz.go
