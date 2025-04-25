// Copyright © 2024, 2025 Attestant Limited.
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

import (
	ssz "github.com/ferranbt/fastssz"
)

// MarshalSSZ ssz marshals the SignedValidatorRegistrations object.
func (s *SignedValidatorRegistrations) MarshalSSZ() ([]byte, error) {
	return ssz.MarshalSSZ(s)
}

// MarshalSSZTo ssz marshals the SignedValidatorRegistrations object to a target array.
// Note that this does not actually marshal the object, just the list inside it.  This means that the resultant encoding does not
// contain an offset, just the elements.
// This is non-standard, but required for conformance with https://ethereum.github.io/builder-specs/#/Builder/registerValidator
// which presents the list as a simple array rather than an object.
// See https://eth2book.info/capella/part2/building_blocks/ssz/#lists for details.
func (s *SignedValidatorRegistrations) MarshalSSZTo(buf []byte) ([]byte, error) {
	dst := buf
	var err error

	if size := len(s.Registrations); size > 1099511627776 {
		return nil, ssz.ErrListTooBigFn("SignedValidatorRegistrations.Registrations", size, 1099511627776)
	}
	for ii := range s.Registrations {
		if dst, err = s.Registrations[ii].MarshalSSZTo(dst); err != nil {
			return nil, err
		}
	}

	return dst, nil
}

// UnmarshalSSZ ssz unmarshals the SignedValidatorRegistrations object.
// Note that this expects the encoded bytes to be a simple list rather than the encoded object, specifically there is not expected
// to be an offset before the registrations.
// This is non-standard, but required for conformance with https://ethereum.github.io/builder-specs/#/Builder/registerValidator
// which presents the list as a simple array rather than an object.
// See https://eth2book.info/capella/part2/building_blocks/ssz/#lists for details.
func (s *SignedValidatorRegistrations) UnmarshalSSZ(buf []byte) error {
	var err error
	size := uint64(len(buf))
	if size < 4 {
		return ssz.ErrSize
	}

	tail := buf
	var o0 uint64

	{
		buf = tail[o0:]
		num, err := ssz.DivideInt2(len(buf), 180, 1099511627776)
		if err != nil {
			return err
		}
		s.Registrations = make([]*SignedValidatorRegistration, num)
		for ii := range num {
			if s.Registrations[ii] == nil {
				s.Registrations[ii] = new(SignedValidatorRegistration)
			}
			if err = s.Registrations[ii].UnmarshalSSZ(buf[ii*180 : (ii+1)*180]); err != nil {
				return err
			}
		}
	}

	return err
}

// SizeSSZ returns the ssz encoded size in bytes for the SignedValidatorRegistrations object.
func (s *SignedValidatorRegistrations) SizeSSZ() int {
	return len(s.Registrations) * 180
}

// HashTreeRoot ssz hashes the SignedValidatorRegistrations object.
func (s *SignedValidatorRegistrations) HashTreeRoot() ([32]byte, error) {
	return ssz.HashWithDefaultHasher(s)
}

// HashTreeRootWith ssz hashes the SignedValidatorRegistrations object with a hasher.
func (s *SignedValidatorRegistrations) HashTreeRootWith(hh ssz.HashWalker) error {
	indx := hh.Index()

	{
		subIndx := hh.Index()
		num := uint64(len(s.Registrations))
		if num > 1099511627776 {
			return ssz.ErrIncorrectListSize
		}
		for _, elem := range s.Registrations {
			if err := elem.HashTreeRootWith(hh); err != nil {
				return err
			}
		}
		hh.MerkleizeWithMixin(subIndx, num, 1099511627776)
	}

	hh.Merkleize(indx)

	return nil
}

// GetTree ssz hashes the SignedValidatorRegistrations object.
func (s *SignedValidatorRegistrations) GetTree() (*ssz.Node, error) {
	return ssz.ProofTree(s)
}
