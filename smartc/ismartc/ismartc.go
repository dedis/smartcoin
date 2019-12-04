package ismartc

import "byzcoin/transaction/itransaction"

// ISmartc ...
type ISmartc interface {
	GetContractConfigID() string
	GetContractDarcID() string
	GetDarcContractIDs() []string
	PrintInstruction(itransaction.Instruction) string
	GetContractRegistry() *ContractRegistry
	RegisterGlobalContract(contractID string, f func(in []byte) (Contract, error)) error
	ContractConfigFromBytes(in []byte) (Contract, error)
	ContractSecureDarcFromBytes(in []byte) (Contract, error)
}

// ContractRegistry ...
type ContractRegistry interface {
	Search(string) (func(in []byte) (Contract, error), bool)
}

// Contract is the interface that an instance needs
// to implement to be callable as a pre-compiled smart
// contract.
type Contract interface {
	Spawn(itransaction.ReadOnlyStateTrie, itransaction.Instruction, itransaction.Transaction) ([]byte, error)
	Invoke(itransaction.ReadOnlyStateTrie, itransaction.Instruction, itransaction.Transaction) ([]byte, error)
	Delete(itransaction.ReadOnlyStateTrie, itransaction.Instruction, itransaction.Transaction) ([]byte, error)
	FormatMethod(itransaction.Instruction) string
}
