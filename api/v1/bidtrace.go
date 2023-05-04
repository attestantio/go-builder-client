package v1

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"strconv"
	"strings"

	"github.com/attestantio/go-eth2-client/spec/bellatrix"
	"github.com/attestantio/go-eth2-client/spec/phase0"
	"github.com/goccy/go-yaml"
	"github.com/holiman/uint256"
	"github.com/pkg/errors"
)

// BidTrace represents a bid trace.
type BidTrace struct {
	Slot                 uint64
	ParentHash           phase0.Hash32              `ssz-size:"32"`
	BlockHash            phase0.Hash32              `ssz-size:"32"`
	BuilderPubkey        phase0.BLSPubKey           `ssz-size:"48"`
	ProposerPubkey       phase0.BLSPubKey           `ssz-size:"48"`
	ProposerFeeRecipient bellatrix.ExecutionAddress `ssz-size:"20"`
	GasLimit             uint64
	GasUsed              uint64
	Value                *uint256.Int `ssz-size:"32"`
}

// bidTraceJSON is the spec representation of the struct.
type bidTraceJSON struct {
	Slot                 string `json:"slot"`
	ParentHash           string `json:"parent_hash"`
	BlockHash            string `json:"block_hash"`
	BuilderPubkey        string `json:"builder_pubkey"`
	ProposerPubkey       string `json:"proposer_pubkey"`
	ProposerFeeRecipient string `json:"proposer_fee_recipient"`
	GasLimit             string `json:"gas_limit"`
	GasUsed              string `json:"gas_used"`
	Value                string `json:"value"`
}

// bidTraceYAML is the spec representation of the struct.
type bidTraceYAML struct {
	Slot                 uint64   `yaml:"slot"`
	ParentHash           string   `yaml:"parent_hash"`
	BlockHash            string   `yaml:"block_hash"`
	BuilderPubkey        string   `yaml:"builder_pubkey"`
	ProposerPubkey       string   `yaml:"proposer_pubkey"`
	ProposerFeeRecipient string   `yaml:"proposer_fee_recipient"`
	GasLimit             uint64   `yaml:"gas_limit"`
	GasUsed              uint64   `yaml:"gas_used"`
	Value                *big.Int `yaml:"value"`
}

// MarshalJSON implements json.Marshaler.
func (b *BidTrace) MarshalJSON() ([]byte, error) {
	return json.Marshal(&bidTraceJSON{
		Slot:                 fmt.Sprintf("%d", b.Slot),
		ParentHash:           fmt.Sprintf("%#x", b.ParentHash),
		BlockHash:            fmt.Sprintf("%#x", b.BlockHash),
		BuilderPubkey:        fmt.Sprintf("%#x", b.BuilderPubkey),
		ProposerPubkey:       fmt.Sprintf("%#x", b.ProposerPubkey),
		ProposerFeeRecipient: b.ProposerFeeRecipient.String(),
		GasLimit:             fmt.Sprintf("%d", b.GasLimit),
		GasUsed:              fmt.Sprintf("%d", b.GasUsed),
		Value:                fmt.Sprintf("%d", b.Value),
	})
}

// UnmarshalJSON implements json.Unmarshaler.
func (b *BidTrace) UnmarshalJSON(input []byte) error {
	var data bidTraceJSON
	if err := json.Unmarshal(input, &data); err != nil {
		return errors.Wrap(err, "invalid JSON")
	}

	return b.unpack(&data)
}

func (b *BidTrace) unpack(data *bidTraceJSON) error {
	if data.Slot == "" {
		return errors.New("slot missing")
	}
	slot, err := strconv.ParseUint(data.Slot, 10, 64)
	if err != nil {
		return errors.Wrap(err, "invalid value for slot")
	}
	b.Slot = slot

	if data.ParentHash == "" {
		return errors.New("parent hash missing")
	}
	parentHash, err := hex.DecodeString(strings.TrimPrefix(data.ParentHash, "0x"))
	if err != nil {
		return errors.Wrap(err, "invalid value for parent hash")
	}
	if len(parentHash) != phase0.Hash32Length {
		return errors.New("incorrect length for parent hash")
	}
	copy(b.ParentHash[:], parentHash)

	if data.BlockHash == "" {
		return errors.New("block hash missing")
	}
	blockHash, err := hex.DecodeString(strings.TrimPrefix(data.BlockHash, "0x"))
	if err != nil {
		return errors.Wrap(err, "invalid value for block hash")
	}
	if len(blockHash) != phase0.Hash32Length {
		return errors.New("incorrect length for block hash")
	}
	copy(b.BlockHash[:], blockHash)

	if data.BuilderPubkey == "" {
		return errors.New("builder pubkey missing")
	}
	builderPubkey, err := hex.DecodeString(strings.TrimPrefix(data.BuilderPubkey, "0x"))
	if err != nil {
		return errors.Wrap(err, "invalid value for builder pubkey")
	}
	if len(builderPubkey) != phase0.PublicKeyLength {
		return errors.New("incorrect length for builder pubkey")
	}
	copy(b.BuilderPubkey[:], builderPubkey)

	if data.ProposerPubkey == "" {
		return errors.New("proposer pubkey missing")
	}
	proposerPubkey, err := hex.DecodeString(strings.TrimPrefix(data.ProposerPubkey, "0x"))
	if err != nil {
		return errors.Wrap(err, "invalid value for proposer pubkey")
	}
	if len(proposerPubkey) != phase0.PublicKeyLength {
		return errors.New("incorrect length for proposer pubkey")
	}
	copy(b.ProposerPubkey[:], proposerPubkey)

	if data.ProposerFeeRecipient == "" {
		return errors.New("proposer fee recipient missing")
	}
	proposerFeeRecipient, err := hex.DecodeString(strings.TrimPrefix(data.ProposerFeeRecipient, "0x"))
	if err != nil {
		return errors.Wrap(err, "invalid value for proposer fee recipient")
	}
	if len(proposerFeeRecipient) != bellatrix.ExecutionAddressLength {
		return errors.New("incorrect length for proposer fee recipient")
	}
	copy(b.ProposerFeeRecipient[:], proposerFeeRecipient)

	if data.GasLimit == "" {
		return errors.New("gas limit missing")
	}
	gasLimit, err := strconv.ParseUint(data.GasLimit, 10, 64)
	if err != nil {
		return errors.Wrap(err, "invalid value for gas limit")
	}
	b.GasLimit = gasLimit

	if data.GasUsed == "" {
		return errors.New("gas used missing")
	}
	gasUsed, err := strconv.ParseUint(data.GasUsed, 10, 64)
	if err != nil {
		return errors.Wrap(err, "invalid value for gas used")
	}
	b.GasUsed = gasUsed

	if data.Value == "" {
		return errors.New("value missing")
	}
	value, success := new(big.Int).SetString(data.Value, 10)
	if !success {
		return errors.New("invalid value for value")
	}
	if value.Sign() == -1 {
		return errors.New("value cannot be negative")
	}
	var overflow bool
	b.Value, overflow = uint256.FromBig(value)
	if overflow {
		return errors.New("value overflow")
	}

	return nil
}

// MarshalYAML implements yaml.Marshaler.
func (b *BidTrace) MarshalYAML() ([]byte, error) {
	yamlBytes, err := yaml.MarshalWithOptions(&bidTraceYAML{
		Slot:                 b.Slot,
		ParentHash:           fmt.Sprintf("%#x", b.ParentHash),
		BlockHash:            fmt.Sprintf("%#x", b.BlockHash),
		BuilderPubkey:        fmt.Sprintf("%#x", b.BuilderPubkey),
		ProposerPubkey:       fmt.Sprintf("%#x", b.ProposerPubkey),
		ProposerFeeRecipient: b.ProposerFeeRecipient.String(),
		GasLimit:             b.GasLimit,
		GasUsed:              b.GasUsed,
		Value:                b.Value.ToBig(),
	}, yaml.Flow(true))
	if err != nil {
		return nil, err
	}

	return bytes.ReplaceAll(yamlBytes, []byte(`"`), []byte(`'`)), nil
}

// UnmarshalYAML implements yaml.Unmarshaler.
func (b *BidTrace) UnmarshalYAML(input []byte) error {
	// We unmarshal to the JSON struct to save on duplicate code.
	var data bidTraceJSON
	if err := yaml.Unmarshal(input, &data); err != nil {
		return err
	}

	return b.unpack(&data)
}

// String returns the string representation of the bid trace.
func (b *BidTrace) String() string {
	data, err := yaml.Marshal(b)
	if err != nil {
		return fmt.Sprintf("ERR: %v", err)
	}

	return string(data)
}
