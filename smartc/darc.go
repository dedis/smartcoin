package smartc

import (
	"bytes"
	"byzcoin/smartc/ismartc"
	"byzcoin/transaction/itransaction"

	"byzcoin/darc"

	"go.dedis.ch/cothority/v3"
	"golang.org/x/xerrors"
)

// ContractDarcID denotes a secure version of the DARC contract. We
// provide two forms of security. The first is "restricted evolution", where
// the evolve command only allows changes to existing rules, it is not allowed
// to add new rules. There exists an additional command "evolve_unrestricted"
// that allows authorised users to change the rules arbitrarily. Our second
// form of security is "controlled spawn", where the rules of the secure darcs
// spawned using this contract are subject to some restrictions, e.g., the new
// rules must not contain spawn:inseucre_darc. While this contract may be
// useful in a lot of scenarios, it is possible to have even more control by
// writing new DARC contracts for the intended application.
const ContractDarcID = "darc"

type contractSecureDarc struct {
	BasicContract
	darc.Darc
	contracts ismartc.ReadOnlyContractRegistry
}

var _ ismartc.Contract = (*contractSecureDarc)(nil)

const cmdDarcEvolveUnrestriction = "evolve_unrestricted"
const cmdDarcEvolve = "evolve"

// ContractSecureDarcFromBytes ...
func ContractSecureDarcFromBytes(in []byte) (ismartc.Contract, error) {
	d, err := darc.NewFromProtobuf(in)
	if err != nil {
		return nil, xerrors.Errorf("darc decoding: %v", err)
	}
	c := &contractSecureDarc{Darc: *d}
	return c, nil
}

// SetRegistry keeps the reference of the contract registry.
func (c *contractSecureDarc) SetRegistry(r ismartc.ReadOnlyContractRegistry) {
	c.contracts = r
}

// VerifyDeferredInstruction does the same as the standard VerifyInstruction
// method in the diferrence that it does not take into account the counters. We
// need the Darc contract to opt in for deferred transaction because it is used
// by default when spawning new contracts.
// func (c *contractSecureDarc) VerifyDeferredInstruction(rst transaction.ReadOnlyStateTrie, inst transaction.Instruction, ctxHash []byte) error {
// 	err := inst.VerifyWithOption(rst, ctxHash, &transaction.VerificationOptions{IgnoreCounters: true})
// 	return cothority.ErrorOrNil(err, "instruction verification")
// }

func (c *contractSecureDarc) Spawn(rst itransaction.ReadOnlyStateTrie, inst itransaction.Instruction, trans itransaction.Transaction) (out []byte, err error) {

	if inst.GetContractID() == ContractDarcID {
		darcBuf := inst.GetArgs().Search("darc")
		d, err := darc.NewFromProtobuf(darcBuf)
		if err != nil {
			return nil, xerrors.Errorf("given DARC could not be decoded: %v", err)
		}
		if d.Version != 0 {
			return nil, xerrors.New("DARC version must start at 0")
		}

		// id := d.GetBaseID()

		// Here is an example hard-coded constraint for spawning DARCs.
		// If the constraint needs to be dynamic, then it is
		// recommended to create a new contract that contains mappings
		// of roles -> identities, and roles -> whitelist of rules.
		// Then modify this contract to check the whitelist.
		if d.Rules.Contains("spawn:insecure_darc") {
			return nil, xerrors.New("a secure DARC is not allowed to spawn an insecure DARC")
		}

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
	if cwr, ok := c2.(ismartc.ContractWithRegistry); ok {
		cwr.SetRegistry(c.contracts)
	}

	scs, err := c2.Spawn(rst, inst, trans)
	return scs, cothority.ErrorOrNil(err, "spawn instance")
}

func (c *contractSecureDarc) Invoke(rst itransaction.ReadOnlyStateTrie, inst itransaction.Instruction, trans itransaction.Transaction) ([]byte, error) {
	command, err := inst.GetCommand()
	if err != nil {
		return nil, xerrors.Errorf("failed to get command: %v", err)
	}
	switch command {
	case cmdDarcEvolve:
		var darcID darc.ID
		_, _, _, darcID, err := rst.GetValues(inst.GetInstanceID().Slice())
		if err != nil {
			return nil, xerrors.Errorf("reading trie: %v", err)
		}

		darcBuf := inst.GetArgs().Search("darc")
		newD, err := darc.NewFromProtobuf(darcBuf)
		if err != nil {
			return nil, xerrors.Errorf("darc encoding: %v", err)
		}
		oldD, err := LoadDarcFromTrie(rst, darcID)
		if err != nil {
			return nil, xerrors.Errorf("darc from trie: %v", err)
		}
		// do not allow modification of evolve_unrestricted
		if isChangingEvolveUnrestricted(oldD, newD) {
			return nil, xerrors.New("the evolve command is not allowed to change the the evolve_unrestricted rule")
		}
		if err := newD.SanityCheck(oldD); err != nil {
			return nil, xerrors.Errorf("sanity check: %v", err)
		}
		// use the subset rule if it's not a genesis Darc
		_, _, _, genesisDarcID, err := GetValueContract(rst, newInstanceID(nil).Slice())
		if err != nil {
			return nil, xerrors.Errorf("getting contract: %v", err)
		}
		if !genesisDarcID.Equal(oldD.GetBaseID()) {
			if !newD.Rules.IsSubset(oldD.Rules) {
				return nil, xerrors.New("rules in the new version must be a subset of the previous version")
			}
		}
		return darcBuf, nil
	case cmdDarcEvolveUnrestriction:
		var darcID darc.ID
		_, _, _, darcID, err := rst.GetValues(inst.GetInstanceID().Slice())
		if err != nil {
			return nil, xerrors.Errorf("reading trie: %v", err)
		}

		darcBuf := inst.GetArgs().Search("darc")
		newD, err := darc.NewFromProtobuf(darcBuf)
		if err != nil {
			return nil, xerrors.Errorf("encoding darc: %v", err)
		}
		oldD, err := LoadDarcFromTrie(rst, darcID)
		if err != nil {
			return nil, xerrors.Errorf("darc from trie: %v", err)
		}
		if err := newD.SanityCheck(oldD); err != nil {
			return nil, xerrors.Errorf("sanity check: %v", err)
		}
		return darcBuf, nil
	default:
		return nil, xerrors.New("invalid command: " + command)
	}
}

func isChangingEvolveUnrestricted(oldD *darc.Darc, newD *darc.Darc) bool {
	oldExpr := oldD.Rules.Get(darc.Action("invoke:" + ContractDarcID + "." + cmdDarcEvolveUnrestriction))
	newExpr := newD.Rules.Get(darc.Action("invoke:" + ContractDarcID + "." + cmdDarcEvolveUnrestriction))
	if len(oldExpr) == 0 && len(newExpr) == 0 {
		return false
	}
	if bytes.Equal(oldExpr, newExpr) {
		return false
	}
	return true
}
