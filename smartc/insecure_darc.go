package smartc

import (
	"byzcoin/smartc/ismartc"
	"byzcoin/transaction/itransaction"

	"go.dedis.ch/cothority/v3/darc"
	"golang.org/x/xerrors"
)

// ContractInsecureDarcID denotes a darc-contract
const ContractInsecureDarcID = "insecure_darc"

type contractInsecureDarc struct {
	BasicContract
	darc.Darc
	contracts ismartc.ReadOnlyContractRegistry
}

var _ ismartc.Contract = (*contractInsecureDarc)(nil)

func contractInsecureDarcFromBytes(in []byte) (ismartc.Contract, error) {
	d, err := darc.NewFromProtobuf(in)
	if err != nil {
		return nil, err
	}
	c := &contractInsecureDarc{Darc: *d}
	return c, nil
}

// SetRegistry keeps the reference of the contract registry.
func (c *contractInsecureDarc) SetRegistry(r ismartc.ReadOnlyContractRegistry) {
	c.contracts = r
}

func (c *contractInsecureDarc) Spawn(rst itransaction.ReadOnlyStateTrie, inst itransaction.Instruction, trans itransaction.Transaction) ([]byte, error) {
	// cout = coins

	if inst.GetContractID() == ContractInsecureDarcID {
		darcBuf := inst.GetArgs().Search("darc")
		d, err := darc.NewFromProtobuf(darcBuf)
		if err != nil {
			return nil, xerrors.Errorf("given darc could not be decoded: %v", err)
		}
		if d.Version != 0 {
			return nil, xerrors.New("DARC version must start at 0")
		}
		// id := d.GetBaseID()
		// return []byzcoin.StateChange{
		// 	byzcoin.NewStateChange(byzcoin.Create, byzcoin.NewInstanceID(id), ContractInsecureDarcID, darcBuf, id),
		// }, coins, nil
		return darcBuf, nil
	}

	// If we got here this is a spawn:xxx in order to spawn
	// a new instance of contract xxx, so do that.

	if c.contracts == nil {
		return nil, xerrors.New("contracts registry is missing due to bad initialization")
	}

	cfact, found := c.contracts.Search(inst.GetContractID())
	if !found {
		return nil, xerrors.New("couldn't find this contract type: " + inst.GetContractID())
	}

	// Pass nil into the contract factory here because this instance does not exist yet.
	// So the factory will make a zero-value instance, and then calling Spawn on it
	// will give it a chance to encode it's zero state and emit one or more StateChanges to put itself
	// into the trie.
	c2, err := cfact(nil)
	if err != nil {
		return nil, xerrors.Errorf("could not spawn new zero instance: %v", err)
	}
	return c2.Spawn(rst, inst, trans)
}

func (c *contractInsecureDarc) Invoke(rst itransaction.ReadOnlyStateTrie, inst itransaction.Instruction, trans itransaction.Transaction) ([]byte, error) {
	command, err := inst.GetCommand()
	if err != nil {
		return nil, xerrors.Errorf("failed to get command: %v", err)
	}
	switch command {
	case "evolve":
		_, _, _, _, err := rst.GetValues(inst.GetInstanceID().Slice())
		if err != nil {
			return nil, err
		}

		darcBuf := inst.GetArgs().Search("darc")
		// newD, err := darc.NewFromProtobuf(darcBuf)
		// if err != nil {
		// 	return nil, err
		// }
		// oldD, err := LoadDarcFromTrie(rst, darcID)
		// if err != nil {
		// 	return nil, err
		// }
		// if err := newD.SanityCheck(oldD); err != nil {
		// 	return nil, err
		// }
		// return []byzcoin.StateChange{
		// 	byzcoin.NewStateChange(byzcoin.Update, inst.InstanceID, ContractInsecureDarcID, darcBuf, darcID),
		// }, coins, nil
		return darcBuf, nil
	default:
		return nil, xerrors.New("invalid command: " + command)
	}
}
