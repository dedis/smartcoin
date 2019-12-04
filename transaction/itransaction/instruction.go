package itransaction

import "byzcoin/darc"

// Instruction ...
type Instruction interface {
	GetType2() int
	IsSpawn(int) bool
	IsInvoke(int) bool
	IsDelete(int) bool
	GetArgs() Arguments
	// GetDarc() []byte
	GetContractID() string
	GetCommand() (string, error)
	GetInstanceID() InstanceID
	GetAction() string
	GetSignerIdentities() []darc.Identity
	GetSignerCounters() []uint64
	GetSignatures() [][]byte
	Hash() []byte
}

// Arguments ...
type Arguments interface {
	Search(string) []byte
	GetAllKeys() []string
}
