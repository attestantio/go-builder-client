package capella

import (
	consensusspec "github.com/attestantio/go-eth2-client/spec"
	"github.com/attestantio/go-eth2-client/spec/capella"
)

// VersionedExecutionPayload contains a versioned ExecutionPayload.
type VersionedExecutionPayload struct {
	Version consensusspec.DataVersion `json:"version"`
	Capella *capella.ExecutionPayload `json:"data,omitempty"`
}

// IsEmpty returns true if there is no payload.
func (v *VersionedExecutionPayload) IsEmpty() bool {
	return v.Capella == nil
}
