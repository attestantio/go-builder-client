package v1_test

import (
	"bytes"
	"encoding/json"
	"testing"

	v1 "github.com/attestantio/go-builder-client/api/v1"
	"github.com/goccy/go-yaml"
	"github.com/stretchr/testify/require"
	"gotest.tools/assert"
)

func TestBidTraceJSON(t *testing.T) {
	tests := []struct {
		name  string
		input []byte
		err   string
	}{
		{
			name: "Empty",
			err:  "unexpected end of JSON input",
		},
		{
			name:  "JSONBad",
			input: []byte(`[]`),
			err:   "invalid JSON: json: cannot unmarshal array into Go value of type v1.bidTraceJSON",
		},
		{
			name:  "SlotMissing",
			input: []byte(`{"parent_hash":"0xae694782c41219774f46891c6365243b97d63d66aeb7827023b8336161615652","block_hash":"0x6462e48cff39c6e4e02e5fe1aa97bf03b23a1aa588f07cfd6296d2b9bb909ce4","builder_pubkey":"0x8efc1675ffb449abc00a6ad8a2808cdf798d96fbb979cf00956012f3983577c9afe69495411a89385421f1cff47dfc98","proposer_pubkey":"0xb7da036d8aedf726e2b3439f95bdf0e68519bb55ab83d5d97a70a5b8510f612ad45a6ecc58b8b5b9b09c6b445491a02b","proposer_fee_recipient":"0x9427A30991170f917d7b83dEf6e44d26577871Ed","gas_limit":"30000000","gas_used":"7675443","value":"22135875749231725"}`),
			err:   "slot missing",
		},
		{
			name:  "SlotWrongType",
			input: []byte(`{"slot":true,"parent_hash":"0xae694782c41219774f46891c6365243b97d63d66aeb7827023b8336161615652","block_hash":"0x6462e48cff39c6e4e02e5fe1aa97bf03b23a1aa588f07cfd6296d2b9bb909ce4","builder_pubkey":"0x8efc1675ffb449abc00a6ad8a2808cdf798d96fbb979cf00956012f3983577c9afe69495411a89385421f1cff47dfc98","proposer_pubkey":"0xb7da036d8aedf726e2b3439f95bdf0e68519bb55ab83d5d97a70a5b8510f612ad45a6ecc58b8b5b9b09c6b445491a02b","proposer_fee_recipient":"0x9427A30991170f917d7b83dEf6e44d26577871Ed","gas_limit":"30000000","gas_used":"7675443","value":"22135875749231725"}`),
			err:   "invalid JSON: json: cannot unmarshal bool into Go struct field bidTraceJSON.slot of type string",
		},
		{
			name:  "SlotInvalidValue",
			input: []byte(`{"slot":"-1","parent_hash":"0xae694782c41219774f46891c6365243b97d63d66aeb7827023b8336161615652","block_hash":"0x6462e48cff39c6e4e02e5fe1aa97bf03b23a1aa588f07cfd6296d2b9bb909ce4","builder_pubkey":"0x8efc1675ffb449abc00a6ad8a2808cdf798d96fbb979cf00956012f3983577c9afe69495411a89385421f1cff47dfc98","proposer_pubkey":"0xb7da036d8aedf726e2b3439f95bdf0e68519bb55ab83d5d97a70a5b8510f612ad45a6ecc58b8b5b9b09c6b445491a02b","proposer_fee_recipient":"0x9427A30991170f917d7b83dEf6e44d26577871Ed","gas_limit":"30000000","gas_used":"7675443","value":"22135875749231725"}`),
			err:   "invalid value for slot: strconv.ParseUint: parsing \"-1\": invalid syntax",
		},
		{
			name:  "ParentHashMissing",
			input: []byte(`{"slot":"1","block_hash":"0x6462e48cff39c6e4e02e5fe1aa97bf03b23a1aa588f07cfd6296d2b9bb909ce4","builder_pubkey":"0x8efc1675ffb449abc00a6ad8a2808cdf798d96fbb979cf00956012f3983577c9afe69495411a89385421f1cff47dfc98","proposer_pubkey":"0xb7da036d8aedf726e2b3439f95bdf0e68519bb55ab83d5d97a70a5b8510f612ad45a6ecc58b8b5b9b09c6b445491a02b","proposer_fee_recipient":"0x9427A30991170f917d7b83dEf6e44d26577871Ed","gas_limit":"30000000","gas_used":"7675443","value":"22135875749231725"}`),
			err:   "parent hash missing",
		},
		{
			name:  "ParentHashWrongType",
			input: []byte(`{"slot":"1","parent_hash":true,"block_hash":"0x6462e48cff39c6e4e02e5fe1aa97bf03b23a1aa588f07cfd6296d2b9bb909ce4","builder_pubkey":"0x8efc1675ffb449abc00a6ad8a2808cdf798d96fbb979cf00956012f3983577c9afe69495411a89385421f1cff47dfc98","proposer_pubkey":"0xb7da036d8aedf726e2b3439f95bdf0e68519bb55ab83d5d97a70a5b8510f612ad45a6ecc58b8b5b9b09c6b445491a02b","proposer_fee_recipient":"0x9427A30991170f917d7b83dEf6e44d26577871Ed","gas_limit":"30000000","gas_used":"7675443","value":"22135875749231725"}`),
			err:   "invalid JSON: json: cannot unmarshal bool into Go struct field bidTraceJSON.parent_hash of type string",
		},
		{
			name:  "ParentHashInvalid",
			input: []byte(`{"slot":"1","parent_hash":"true","block_hash":"0x6462e48cff39c6e4e02e5fe1aa97bf03b23a1aa588f07cfd6296d2b9bb909ce4","builder_pubkey":"0x8efc1675ffb449abc00a6ad8a2808cdf798d96fbb979cf00956012f3983577c9afe69495411a89385421f1cff47dfc98","proposer_pubkey":"0xb7da036d8aedf726e2b3439f95bdf0e68519bb55ab83d5d97a70a5b8510f612ad45a6ecc58b8b5b9b09c6b445491a02b","proposer_fee_recipient":"0x9427A30991170f917d7b83dEf6e44d26577871Ed","gas_limit":"30000000","gas_used":"7675443","value":"22135875749231725"}`),
			err:   "invalid value for parent hash: encoding/hex: invalid byte: U+0074 't'",
		},
		{
			name:  "ParentHashWrongLength",
			input: []byte(`{"slot":"1","parent_hash":"0x694782c41219774f46891c6365243b97d63d66aeb7827023b8336161615652","block_hash":"0x6462e48cff39c6e4e02e5fe1aa97bf03b23a1aa588f07cfd6296d2b9bb909ce4","builder_pubkey":"0x8efc1675ffb449abc00a6ad8a2808cdf798d96fbb979cf00956012f3983577c9afe69495411a89385421f1cff47dfc98","proposer_pubkey":"0xb7da036d8aedf726e2b3439f95bdf0e68519bb55ab83d5d97a70a5b8510f612ad45a6ecc58b8b5b9b09c6b445491a02b","proposer_fee_recipient":"0x9427A30991170f917d7b83dEf6e44d26577871Ed","gas_limit":"30000000","gas_used":"7675443","value":"22135875749231725"}`),
			err:   "incorrect length for parent hash",
		},
		{
			name:  "BlockHashMissing",
			input: []byte(`{"slot":"4732647","parent_hash":"0xae694782c41219774f46891c6365243b97d63d66aeb7827023b8336161615652","builder_pubkey":"0x8efc1675ffb449abc00a6ad8a2808cdf798d96fbb979cf00956012f3983577c9afe69495411a89385421f1cff47dfc98","proposer_pubkey":"0xb7da036d8aedf726e2b3439f95bdf0e68519bb55ab83d5d97a70a5b8510f612ad45a6ecc58b8b5b9b09c6b445491a02b","proposer_fee_recipient":"0x9427A30991170f917d7b83dEf6e44d26577871Ed","gas_limit":"30000000","gas_used":"7675443","value":"22135875749231725"}`),
			err:   "block hash missing",
		},
		{
			name:  "BlockHashWrongType",
			input: []byte(`{"slot":"1","parent_hash":"0xae694782c41219774f46891c6365243b97d63d66aeb7827023b8336161615652","block_hash":"0x6462e48cff39c6e4e02e5fe1aa97bf03b23a1aa588f07cfd6296d2b9bb909ce4","block_hash":true,"builder_pubkey":"0x8efc1675ffb449abc00a6ad8a2808cdf798d96fbb979cf00956012f3983577c9afe69495411a89385421f1cff47dfc98","proposer_pubkey":"0xb7da036d8aedf726e2b3439f95bdf0e68519bb55ab83d5d97a70a5b8510f612ad45a6ecc58b8b5b9b09c6b445491a02b","proposer_fee_recipient":"0x9427A30991170f917d7b83dEf6e44d26577871Ed","gas_limit":"30000000","gas_used":"7675443","value":"22135875749231725"}`),
			err:   "invalid JSON: json: cannot unmarshal bool into Go struct field bidTraceJSON.block_hash of type string",
		},
		{
			name:  "BlockHashInvalid",
			input: []byte(`{"slot":"1","parent_hash":"0xae694782c41219774f46891c6365243b97d63d66aeb7827023b8336161615652","block_hash":"true","builder_pubkey":"0x8efc1675ffb449abc00a6ad8a2808cdf798d96fbb979cf00956012f3983577c9afe69495411a89385421f1cff47dfc98","proposer_pubkey":"0xb7da036d8aedf726e2b3439f95bdf0e68519bb55ab83d5d97a70a5b8510f612ad45a6ecc58b8b5b9b09c6b445491a02b","proposer_fee_recipient":"0x9427A30991170f917d7b83dEf6e44d26577871Ed","gas_limit":"30000000","gas_used":"7675443","value":"22135875749231725"}`),
			err:   "invalid value for block hash: encoding/hex: invalid byte: U+0074 't'",
		},
		{
			name:  "BlockHashWrongLength",
			input: []byte(`{"slot":"1","parent_hash":"0xae694782c41219774f46891c6365243b97d63d66aeb7827023b8336161615652","block_hash":"0xe48cff39c6e4e02e5fe1aa97bf03b23a1aa588f07cfd6296d2b9bb909ce4","builder_pubkey":"0x8efc1675ffb449abc00a6ad8a2808cdf798d96fbb979cf00956012f3983577c9afe69495411a89385421f1cff47dfc98","proposer_pubkey":"0xb7da036d8aedf726e2b3439f95bdf0e68519bb55ab83d5d97a70a5b8510f612ad45a6ecc58b8b5b9b09c6b445491a02b","proposer_fee_recipient":"0x9427A30991170f917d7b83dEf6e44d26577871Ed","gas_limit":"30000000","gas_used":"7675443","value":"22135875749231725"}`),
			err:   "incorrect length for block hash",
		},
		{
			name:  "BuilderPubkeyMissing",
			input: []byte(`{"slot":"1","parent_hash":"0xae694782c41219774f46891c6365243b97d63d66aeb7827023b8336161615652","block_hash":"0x6462e48cff39c6e4e02e5fe1aa97bf03b23a1aa588f07cfd6296d2b9bb909ce4","proposer_pubkey":"0xb7da036d8aedf726e2b3439f95bdf0e68519bb55ab83d5d97a70a5b8510f612ad45a6ecc58b8b5b9b09c6b445491a02b","proposer_fee_recipient":"0x9427A30991170f917d7b83dEf6e44d26577871Ed","gas_limit":"30000000","gas_used":"7675443","value":"22135875749231725"}`),
			err:   "builder pubkey missing",
		},
		{
			name:  "BuilderPubkeyWrongType",
			input: []byte(`{"slot":"1","parent_hash":"0xae694782c41219774f46891c6365243b97d63d66aeb7827023b8336161615652","block_hash":"0x6462e48cff39c6e4e02e5fe1aa97bf03b23a1aa588f07cfd6296d2b9bb909ce4","builder_pubkey":true,"proposer_pubkey":"0xb7da036d8aedf726e2b3439f95bdf0e68519bb55ab83d5d97a70a5b8510f612ad45a6ecc58b8b5b9b09c6b445491a02b","proposer_fee_recipient":"0x9427A30991170f917d7b83dEf6e44d26577871Ed","gas_limit":"30000000","gas_used":"7675443","value":"22135875749231725"}`),
			err:   "invalid JSON: json: cannot unmarshal bool into Go struct field bidTraceJSON.builder_pubkey of type string",
		},
		{
			name:  "BuilderPubkeyInvalid",
			input: []byte(`{"slot":"1","parent_hash":"0xae694782c41219774f46891c6365243b97d63d66aeb7827023b8336161615652","block_hash":"0x6462e48cff39c6e4e02e5fe1aa97bf03b23a1aa588f07cfd6296d2b9bb909ce4","builder_pubkey":"true","proposer_pubkey":"0xb7da036d8aedf726e2b3439f95bdf0e68519bb55ab83d5d97a70a5b8510f612ad45a6ecc58b8b5b9b09c6b445491a02b","proposer_fee_recipient":"0x9427A30991170f917d7b83dEf6e44d26577871Ed","gas_limit":"30000000","gas_used":"7675443","value":"22135875749231725"}`),
			err:   "invalid value for builder pubkey: encoding/hex: invalid byte: U+0074 't'",
		},
		{
			name:  "BuilderPubkeyIncorrectLength",
			input: []byte(`{"slot":"1","parent_hash":"0xae694782c41219774f46891c6365243b97d63d66aeb7827023b8336161615652","block_hash":"0x6462e48cff39c6e4e02e5fe1aa97bf03b23a1aa588f07cfd6296d2b9bb909ce4","builder_pubkey":"0xfc1675ffb449abc00a6ad8a2808cdf798d96fbb979cf00956012f3983577c9afe69495411a89385421f1cff47dfc98","proposer_pubkey":"0xb7da036d8aedf726e2b3439f95bdf0e68519bb55ab83d5d97a70a5b8510f612ad45a6ecc58b8b5b9b09c6b445491a02b","proposer_fee_recipient":"0x9427A30991170f917d7b83dEf6e44d26577871Ed","gas_limit":"30000000","gas_used":"7675443","value":"22135875749231725"}`),
			err:   "incorrect length for builder pubkey",
		},
		{
			name:  "ProposerPubkeyMissing",
			input: []byte(`{"slot":"1","parent_hash":"0xae694782c41219774f46891c6365243b97d63d66aeb7827023b8336161615652","block_hash":"0x6462e48cff39c6e4e02e5fe1aa97bf03b23a1aa588f07cfd6296d2b9bb909ce4","builder_pubkey":"0x8efc1675ffb449abc00a6ad8a2808cdf798d96fbb979cf00956012f3983577c9afe69495411a89385421f1cff47dfc98","proposer_fee_recipient":"0x9427A30991170f917d7b83dEf6e44d26577871Ed","gas_limit":"30000000","gas_used":"7675443","value":"22135875749231725"}`),
			err:   "proposer pubkey missing",
		},
		{
			name:  "ProposerPubkeyWrongType",
			input: []byte(`{"slot":"1","parent_hash":"0xae694782c41219774f46891c6365243b97d63d66aeb7827023b8336161615652","block_hash":"0x6462e48cff39c6e4e02e5fe1aa97bf03b23a1aa588f07cfd6296d2b9bb909ce4","builder_pubkey":"0x8efc1675ffb449abc00a6ad8a2808cdf798d96fbb979cf00956012f3983577c9afe69495411a89385421f1cff47dfc98","proposer_pubkey":true,"proposer_fee_recipient":"0x9427A30991170f917d7b83dEf6e44d26577871Ed","gas_limit":"30000000","gas_used":"7675443","value":"22135875749231725"}`),
			err:   "invalid JSON: json: cannot unmarshal bool into Go struct field bidTraceJSON.proposer_pubkey of type string",
		},
		{
			name:  "ProposerPubkeyInvalid",
			input: []byte(`{"slot":"1","parent_hash":"0xae694782c41219774f46891c6365243b97d63d66aeb7827023b8336161615652","block_hash":"0x6462e48cff39c6e4e02e5fe1aa97bf03b23a1aa588f07cfd6296d2b9bb909ce4","builder_pubkey":"0x8efc1675ffb449abc00a6ad8a2808cdf798d96fbb979cf00956012f3983577c9afe69495411a89385421f1cff47dfc98","proposer_pubkey":"true","proposer_fee_recipient":"0x9427A30991170f917d7b83dEf6e44d26577871Ed","gas_limit":"30000000","gas_used":"7675443","value":"22135875749231725"}`),
			err:   "invalid value for proposer pubkey: encoding/hex: invalid byte: U+0074 't'",
		},
		{
			name:  "ProposerPubkeyIncorrectLength",
			input: []byte(`{"slot":"1","parent_hash":"0xae694782c41219774f46891c6365243b97d63d66aeb7827023b8336161615652","block_hash":"0x6462e48cff39c6e4e02e5fe1aa97bf03b23a1aa588f07cfd6296d2b9bb909ce4","builder_pubkey":"0x8efc1675ffb449abc00a6ad8a2808cdf798d96fbb979cf00956012f3983577c9afe69495411a89385421f1cff47dfc98","proposer_pubkey":"0xda036d8aedf726e2b3439f95bdf0e68519bb55ab83d5d97a70a5b8510f612ad45a6ecc58b8b5b9b09c6b445491a02b","proposer_fee_recipient":"0x9427A30991170f917d7b83dEf6e44d26577871Ed","gas_limit":"30000000","gas_used":"7675443","value":"22135875749231725"}`),
			err:   "incorrect length for proposer pubkey",
		},
		{
			name:  "FeeRecipientMissing",
			input: []byte(`{"slot":"1","parent_hash":"0xae694782c41219774f46891c6365243b97d63d66aeb7827023b8336161615652","block_hash":"0x6462e48cff39c6e4e02e5fe1aa97bf03b23a1aa588f07cfd6296d2b9bb909ce4","builder_pubkey":"0x8efc1675ffb449abc00a6ad8a2808cdf798d96fbb979cf00956012f3983577c9afe69495411a89385421f1cff47dfc98","proposer_pubkey":"0xb7da036d8aedf726e2b3439f95bdf0e68519bb55ab83d5d97a70a5b8510f612ad45a6ecc58b8b5b9b09c6b445491a02b","gas_limit":"30000000","gas_used":"7675443","value":"22135875749231725"}`),
			err:   "proposer fee recipient missing",
		},
		{
			name:  "FeeRecipientWrongType",
			input: []byte(`{"slot":"1","parent_hash":"0xae694782c41219774f46891c6365243b97d63d66aeb7827023b8336161615652","block_hash":"0x6462e48cff39c6e4e02e5fe1aa97bf03b23a1aa588f07cfd6296d2b9bb909ce4","builder_pubkey":"0x8efc1675ffb449abc00a6ad8a2808cdf798d96fbb979cf00956012f3983577c9afe69495411a89385421f1cff47dfc98","proposer_pubkey":"0xb7da036d8aedf726e2b3439f95bdf0e68519bb55ab83d5d97a70a5b8510f612ad45a6ecc58b8b5b9b09c6b445491a02b","proposer_fee_recipient":true,"gas_limit":"30000000","gas_used":"7675443","value":"22135875749231725"}`),
			err:   "invalid JSON: json: cannot unmarshal bool into Go struct field bidTraceJSON.proposer_fee_recipient of type string",
		},
		{
			name:  "FeeReceipientInvalid",
			input: []byte(`{"slot":"1","parent_hash":"0xae694782c41219774f46891c6365243b97d63d66aeb7827023b8336161615652","block_hash":"0x6462e48cff39c6e4e02e5fe1aa97bf03b23a1aa588f07cfd6296d2b9bb909ce4","builder_pubkey":"0x8efc1675ffb449abc00a6ad8a2808cdf798d96fbb979cf00956012f3983577c9afe69495411a89385421f1cff47dfc98","proposer_pubkey":"0xb7da036d8aedf726e2b3439f95bdf0e68519bb55ab83d5d97a70a5b8510f612ad45a6ecc58b8b5b9b09c6b445491a02b","proposer_fee_recipient":"true","gas_limit":"30000000","gas_used":"7675443","value":"22135875749231725"}`),
			err:   "invalid value for proposer fee recipient: encoding/hex: invalid byte: U+0074 't'",
		},
		{
			name:  "FeeRecipientWrongLength",
			input: []byte(`{"slot":"1","parent_hash":"0xae694782c41219774f46891c6365243b97d63d66aeb7827023b8336161615652","block_hash":"0x6462e48cff39c6e4e02e5fe1aa97bf03b23a1aa588f07cfd6296d2b9bb909ce4","builder_pubkey":"0x8efc1675ffb449abc00a6ad8a2808cdf798d96fbb979cf00956012f3983577c9afe69495411a89385421f1cff47dfc98","proposer_pubkey":"0xb7da036d8aedf726e2b3439f95bdf0e68519bb55ab83d5d97a70a5b8510f612ad45a6ecc58b8b5b9b09c6b445491a02b","proposer_fee_recipient":"0x27a30991170f917d7b83def6e44d26577871ed","gas_limit":"30000000","gas_used":"7675443","value":"22135875749231725"}`),
			err:   "incorrect length for proposer fee recipient",
		},
		{
			name:  "GasLimitMissing",
			input: []byte(`{"slot":"1","parent_hash":"0xae694782c41219774f46891c6365243b97d63d66aeb7827023b8336161615652","block_hash":"0x6462e48cff39c6e4e02e5fe1aa97bf03b23a1aa588f07cfd6296d2b9bb909ce4","builder_pubkey":"0x8efc1675ffb449abc00a6ad8a2808cdf798d96fbb979cf00956012f3983577c9afe69495411a89385421f1cff47dfc98","proposer_pubkey":"0xb7da036d8aedf726e2b3439f95bdf0e68519bb55ab83d5d97a70a5b8510f612ad45a6ecc58b8b5b9b09c6b445491a02b","proposer_fee_recipient":"0x9427A30991170f917d7b83dEf6e44d26577871Ed","gas_used":"7675443","value":"22135875749231725"}`),
			err:   "gas limit missing",
		},
		{
			name:  "GasLimitWrongType",
			input: []byte(`{"slot":"1","parent_hash":"0xae694782c41219774f46891c6365243b97d63d66aeb7827023b8336161615652","block_hash":"0x6462e48cff39c6e4e02e5fe1aa97bf03b23a1aa588f07cfd6296d2b9bb909ce4","builder_pubkey":"0x8efc1675ffb449abc00a6ad8a2808cdf798d96fbb979cf00956012f3983577c9afe69495411a89385421f1cff47dfc98","proposer_pubkey":"0xb7da036d8aedf726e2b3439f95bdf0e68519bb55ab83d5d97a70a5b8510f612ad45a6ecc58b8b5b9b09c6b445491a02b","proposer_fee_recipient":"0x9427A30991170f917d7b83dEf6e44d26577871Ed","gas_limit":true,"gas_used":"7675443","value":"22135875749231725"}`),
			err:   "invalid JSON: json: cannot unmarshal bool into Go struct field bidTraceJSON.gas_limit of type string",
		},
		{
			name:  "GasLimitInvalid",
			input: []byte(`{"slot":"1","parent_hash":"0xae694782c41219774f46891c6365243b97d63d66aeb7827023b8336161615652","block_hash":"0x6462e48cff39c6e4e02e5fe1aa97bf03b23a1aa588f07cfd6296d2b9bb909ce4","builder_pubkey":"0x8efc1675ffb449abc00a6ad8a2808cdf798d96fbb979cf00956012f3983577c9afe69495411a89385421f1cff47dfc98","proposer_pubkey":"0xb7da036d8aedf726e2b3439f95bdf0e68519bb55ab83d5d97a70a5b8510f612ad45a6ecc58b8b5b9b09c6b445491a02b","proposer_fee_recipient":"0x9427A30991170f917d7b83dEf6e44d26577871Ed","gas_limit":"-1","gas_used":"7675443","value":"22135875749231725"}`),
			err:   "invalid value for gas limit: strconv.ParseUint: parsing \"-1\": invalid syntax",
		},
		{
			name:  "GasUsedMissing",
			input: []byte(`{"slot":"1","parent_hash":"0xae694782c41219774f46891c6365243b97d63d66aeb7827023b8336161615652","block_hash":"0x6462e48cff39c6e4e02e5fe1aa97bf03b23a1aa588f07cfd6296d2b9bb909ce4","builder_pubkey":"0x8efc1675ffb449abc00a6ad8a2808cdf798d96fbb979cf00956012f3983577c9afe69495411a89385421f1cff47dfc98","proposer_pubkey":"0xb7da036d8aedf726e2b3439f95bdf0e68519bb55ab83d5d97a70a5b8510f612ad45a6ecc58b8b5b9b09c6b445491a02b","proposer_fee_recipient":"0x9427A30991170f917d7b83dEf6e44d26577871Ed","gas_limit":"30000000","value":"22135875749231725"}`),
			err:   "gas used missing",
		},
		{
			name:  "GasUsedWrongType",
			input: []byte(`{"slot":"1","parent_hash":"0xae694782c41219774f46891c6365243b97d63d66aeb7827023b8336161615652","block_hash":"0x6462e48cff39c6e4e02e5fe1aa97bf03b23a1aa588f07cfd6296d2b9bb909ce4","builder_pubkey":"0x8efc1675ffb449abc00a6ad8a2808cdf798d96fbb979cf00956012f3983577c9afe69495411a89385421f1cff47dfc98","proposer_pubkey":"0xb7da036d8aedf726e2b3439f95bdf0e68519bb55ab83d5d97a70a5b8510f612ad45a6ecc58b8b5b9b09c6b445491a02b","proposer_fee_recipient":"0x9427A30991170f917d7b83dEf6e44d26577871Ed","gas_limit":"30000000","gas_used":true,"value":"22135875749231725"}`),
			err:   "invalid JSON: json: cannot unmarshal bool into Go struct field bidTraceJSON.gas_used of type string",
		},
		{
			name:  "GasUsedInvalid",
			input: []byte(`{"slot":"1","parent_hash":"0xae694782c41219774f46891c6365243b97d63d66aeb7827023b8336161615652","block_hash":"0x6462e48cff39c6e4e02e5fe1aa97bf03b23a1aa588f07cfd6296d2b9bb909ce4","builder_pubkey":"0x8efc1675ffb449abc00a6ad8a2808cdf798d96fbb979cf00956012f3983577c9afe69495411a89385421f1cff47dfc98","proposer_pubkey":"0xb7da036d8aedf726e2b3439f95bdf0e68519bb55ab83d5d97a70a5b8510f612ad45a6ecc58b8b5b9b09c6b445491a02b","proposer_fee_recipient":"0x9427A30991170f917d7b83dEf6e44d26577871Ed","gas_limit":"30000000","gas_used":"-1","value":"22135875749231725"}`),
			err:   "invalid value for gas used: strconv.ParseUint: parsing \"-1\": invalid syntax",
		},
		{
			name:  "ValueMissing",
			input: []byte(`{"slot":"1","parent_hash":"0xae694782c41219774f46891c6365243b97d63d66aeb7827023b8336161615652","block_hash":"0x6462e48cff39c6e4e02e5fe1aa97bf03b23a1aa588f07cfd6296d2b9bb909ce4","builder_pubkey":"0x8efc1675ffb449abc00a6ad8a2808cdf798d96fbb979cf00956012f3983577c9afe69495411a89385421f1cff47dfc98","proposer_pubkey":"0xb7da036d8aedf726e2b3439f95bdf0e68519bb55ab83d5d97a70a5b8510f612ad45a6ecc58b8b5b9b09c6b445491a02b","proposer_fee_recipient":"0x9427A30991170f917d7b83dEf6e44d26577871Ed","gas_limit":"30000000","gas_used":"7675443"}`),
			err:   "value missing",
		},
		{
			name:  "ValueWrongType",
			input: []byte(`{"slot":"1","parent_hash":"0xae694782c41219774f46891c6365243b97d63d66aeb7827023b8336161615652","block_hash":"0x6462e48cff39c6e4e02e5fe1aa97bf03b23a1aa588f07cfd6296d2b9bb909ce4","builder_pubkey":"0x8efc1675ffb449abc00a6ad8a2808cdf798d96fbb979cf00956012f3983577c9afe69495411a89385421f1cff47dfc98","proposer_pubkey":"0xb7da036d8aedf726e2b3439f95bdf0e68519bb55ab83d5d97a70a5b8510f612ad45a6ecc58b8b5b9b09c6b445491a02b","proposer_fee_recipient":"0x9427A30991170f917d7b83dEf6e44d26577871Ed","gas_limit":"30000000","gas_used":"7675443","value":true}`),
			err:   "invalid JSON: json: cannot unmarshal bool into Go struct field bidTraceJSON.value of type string",
		},
		{
			name:  "ValueInvalid",
			input: []byte(`{"slot":"1","parent_hash":"0xae694782c41219774f46891c6365243b97d63d66aeb7827023b8336161615652","block_hash":"0x6462e48cff39c6e4e02e5fe1aa97bf03b23a1aa588f07cfd6296d2b9bb909ce4","builder_pubkey":"0x8efc1675ffb449abc00a6ad8a2808cdf798d96fbb979cf00956012f3983577c9afe69495411a89385421f1cff47dfc98","proposer_pubkey":"0xb7da036d8aedf726e2b3439f95bdf0e68519bb55ab83d5d97a70a5b8510f612ad45a6ecc58b8b5b9b09c6b445491a02b","proposer_fee_recipient":"0x9427A30991170f917d7b83dEf6e44d26577871Ed","gas_limit":"30000000","gas_used":"7675443","value":"invalid"}`),
			err:   "invalid value for value",
		},
		{
			name:  "ValueOverflow",
			input: []byte(`{"slot":"1","parent_hash":"0xae694782c41219774f46891c6365243b97d63d66aeb7827023b8336161615652","block_hash":"0x6462e48cff39c6e4e02e5fe1aa97bf03b23a1aa588f07cfd6296d2b9bb909ce4","builder_pubkey":"0x8efc1675ffb449abc00a6ad8a2808cdf798d96fbb979cf00956012f3983577c9afe69495411a89385421f1cff47dfc98","proposer_pubkey":"0xb7da036d8aedf726e2b3439f95bdf0e68519bb55ab83d5d97a70a5b8510f612ad45a6ecc58b8b5b9b09c6b445491a02b","proposer_fee_recipient":"0x9427A30991170f917d7b83dEf6e44d26577871Ed","gas_limit":"30000000","gas_used":"7675443","value":"115792089237316195423570985008687907853269984665640564039457584007913129639937"}`),
			err:   "value overflow",
		},
		{
			name:  "ValueNegative",
			input: []byte(`{"slot":"1","parent_hash":"0xae694782c41219774f46891c6365243b97d63d66aeb7827023b8336161615652","block_hash":"0x6462e48cff39c6e4e02e5fe1aa97bf03b23a1aa588f07cfd6296d2b9bb909ce4","builder_pubkey":"0x8efc1675ffb449abc00a6ad8a2808cdf798d96fbb979cf00956012f3983577c9afe69495411a89385421f1cff47dfc98","proposer_pubkey":"0xb7da036d8aedf726e2b3439f95bdf0e68519bb55ab83d5d97a70a5b8510f612ad45a6ecc58b8b5b9b09c6b445491a02b","proposer_fee_recipient":"0x9427A30991170f917d7b83dEf6e44d26577871Ed","gas_limit":"30000000","gas_used":"7675443","value":"-12345"}`),
			err:   "value cannot be negative",
		},
		{
			name:  "Good",
			input: []byte(`{"slot":"1","parent_hash":"0xae694782c41219774f46891c6365243b97d63d66aeb7827023b8336161615652","block_hash":"0x6462e48cff39c6e4e02e5fe1aa97bf03b23a1aa588f07cfd6296d2b9bb909ce4","builder_pubkey":"0x8efc1675ffb449abc00a6ad8a2808cdf798d96fbb979cf00956012f3983577c9afe69495411a89385421f1cff47dfc98","proposer_pubkey":"0xb7da036d8aedf726e2b3439f95bdf0e68519bb55ab83d5d97a70a5b8510f612ad45a6ecc58b8b5b9b09c6b445491a02b","proposer_fee_recipient":"0x9427A30991170f917d7b83dEf6e44d26577871Ed","gas_limit":"30000000","gas_used":"7675443","value":"22135875749231725"}`),
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var res v1.BidTrace
			err := json.Unmarshal(test.input, &res)
			if test.err != "" {
				require.EqualError(t, err, test.err)
			} else {
				require.NoError(t, err)
				rt, err := json.Marshal(&res)
				require.NoError(t, err)
				assert.Equal(t, string(test.input), string(rt))
			}
		})
	}
}

func TestBidTraceYAML(t *testing.T) {
	tests := []struct {
		name  string
		input []byte
		root  []byte
		err   string
	}{
		{
			name:  "Good",
			input: []byte(`{slot: 1, parent_hash: '0xae694782c41219774f46891c6365243b97d63d66aeb7827023b8336161615652', block_hash: '0x6462e48cff39c6e4e02e5fe1aa97bf03b23a1aa588f07cfd6296d2b9bb909ce4', builder_pubkey: '0x8efc1675ffb449abc00a6ad8a2808cdf798d96fbb979cf00956012f3983577c9afe69495411a89385421f1cff47dfc98', proposer_pubkey: '0xb7da036d8aedf726e2b3439f95bdf0e68519bb55ab83d5d97a70a5b8510f612ad45a6ecc58b8b5b9b09c6b445491a02b', proposer_fee_recipient: '0x9427A30991170f917d7b83dEf6e44d26577871Ed', gas_limit: 30000000, gas_used: 7675443, value: 22135875749231725}`),
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var res v1.BidTrace
			err := yaml.Unmarshal(test.input, &res)
			if test.err != "" {
				require.EqualError(t, err, test.err)
			} else {
				require.NoError(t, err)
				rt, err := yaml.Marshal(&res)
				require.NoError(t, err)

				t.Log(string(rt))

				assert.Equal(t, string(rt), res.String())
				rt = bytes.TrimSuffix(rt, []byte("\n"))
				assert.Equal(t, string(test.input), string(rt))
			}
		})
	}
}
