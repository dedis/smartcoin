package itransaction

import "byzcoin/darc"

// ReadOnlyStateTrie ...
type ReadOnlyStateTrie interface {
	GetValues(key []byte) (value []byte, version uint64, contractID string, darcID darc.ID, err error)
}
