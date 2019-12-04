package itransaction

import "go.dedis.ch/kyber/v3/pairing"

// Transaction ...
type Transaction interface {
	GetPairingSuite() pairing.Suite
	GetServiceName() string
}
