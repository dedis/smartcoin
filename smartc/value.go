package smartc

import (
	"byzcoin/smartc/ismartc"
	"byzcoin/transaction/itransaction"

	"golang.org/x/xerrors"
)

// The value contract can simply store a value in an instance and serves
// mainly as a template for other contracts. It helps show the possibilities
// of the contracts and how to use them at a very simple example.

// ContractValueID denotes a contract that can store and update
// key values.
var ContractValueID = "value"

// ContractValue is a simple key/value storage where you
// can put any data inside as wished.
// It can spawn new value instances and will store the "value" argument in these
// new instances. Existing value instances can be updated and deleted.
type ContractValue struct {
	BasicContract
	value []byte
}

func contractValueFromBytes(in []byte) (ismartc.Contract, error) {
	return &ContractValue{value: in}, nil
}

// Spawn implements the transaction.Contract interface
func (c ContractValue) Spawn(rst itransaction.ReadOnlyStateTrie, inst itransaction.Instruction, trans itransaction.Transaction) (sc []byte, err error) {
	// Find the darcID for this instance.
	// var darcID darc.ID
	// _, _, _, darcID, err = rst.GetValues(inst.GetInstanceID().Slice())
	// if err != nil {
	// 	return
	// }

	// sc = []transaction.StateChange{
	// 	transaction.NewStateChange(transaction.Create, inst.DeriveID(""),
	// 		ContractValueID, inst.Spawn.Args.Search("value"), darcID),
	// }
	return inst.GetArgs().Search("value"), nil
}

// Invoke implements the transaction.Contract interface
func (c ContractValue) Invoke(rst itransaction.ReadOnlyStateTrie, inst itransaction.Instruction, trans itransaction.Transaction) (sc []byte, err error) {
	// cout = coins

	// Find the darcID for this instance.
	// var darcID darc.ID

	// _, _, _, darcID, err = rst.GetValues(inst.InstanceID.Slice())
	// if err != nil {
	// 	return
	// }
	command, err := inst.GetCommand()
	switch command {
	case "update":
		// sc = []transaction.StateChange{
		// 	transaction.NewStateChange(transaction.Update, inst.InstanceID,
		// 		ContractValueID, inst.Invoke.Args.Search("value"), darcID),
		// }
		return inst.GetArgs().Search("value"), nil
	default:
		return nil, xerrors.New("Value contract can only update")
	}
}

// Delete implements the transaction.Contract interface
func (c ContractValue) Delete(rst itransaction.ReadOnlyStateTrie, inst itransaction.Instruction, trans itransaction.Transaction) (sc []byte, err error) {
	// cout = coins

	// Find the darcID for this instance.
	// var darcID darc.ID
	// _, _, _, darcID, err = rst.GetValues(inst.InstanceID.Slice())
	// if err != nil {
	// 	return
	// }

	// sc = transaction.StateChanges{
	// 	transaction.NewStateChange(transaction.Remove, inst.InstanceID, ContractValueID, nil, darcID),
	// }
	return nil, nil
}

// VerifyDeferredInstruction implements the transaction.Contract interface
// func (c ContractValue) VerifyDeferredInstruction(rst transaction.ReadOnlyStateTrie, inst transaction.Instruction, ctxHash []byte) error {
// 	return inst.VerifyWithOption(rst, ctxHash, &transaction.VerificationOptions{IgnoreCounters: true})
// }
