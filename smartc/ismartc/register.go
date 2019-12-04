package ismartc

// Registration ...
type Registration interface {
	RegisterContract(string) error
}

// ReadOnlyContractRegistry is the read-only interface for the contract registry.
type ReadOnlyContractRegistry interface {
	Search(contractID string) (func(in []byte) (Contract, error), bool)
}

// ContractWithRegistry is an interface to detect contracts that need a reference
// to the registry.
type ContractWithRegistry interface {
	SetRegistry(ReadOnlyContractRegistry)
}
