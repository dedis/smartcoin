package smartc

import (
	"encoding/binary"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"byzcoin/smartc/ismartc"
	"byzcoin/transaction/itransaction"

	"byzcoin/darc"
	"byzcoin/darc/expression"

	"go.dedis.ch/cothority/v3"
	"go.dedis.ch/cothority/v3/blscosi/protocol"
	"go.dedis.ch/cothority/v3/byzcoin/viewchange"
	"go.dedis.ch/onet/v3"
	"go.dedis.ch/onet/v3/network"
	"go.dedis.ch/protobuf"
	"golang.org/x/xerrors"
)

// EachLine matches the content of non-empty lines
var EachLine = regexp.MustCompile(`(?m)^(.+)$`)

type smartc struct {
}

func (s smartc) GetContractConfigID() string {
	return ContractConfigID
}

func (s smartc) PrintInstruction(instr itransaction.Instruction) string {
	contractFn, ok := GetContractRegistry().Search(instr.GetContractID())
	var methodStr string
	if !ok {
		methodStr = "error in getting constructor: " + instr.GetContractID()
	} else {
		contract, err := contractFn(nil)
		if err != nil {
			methodStr = "error in getting contract"
		} else {
			methodStr = contract.FormatMethod(instr)
		}
	}

	var out strings.Builder
	out.WriteString("- instruction:\n")
	fmt.Fprintf(&out, "-- hash: %x\n", instr.Hash())
	fmt.Fprintf(&out, "-- instID: %v\n", instr.GetInstanceID())
	fmt.Fprintf(&out, "-- action: %s\n", instr.GetAction())
	fmt.Fprintf(&out, "-- identities: %v\n", instr.GetSignerIdentities())
	fmt.Fprintf(&out, "-- counters: %v\n", instr.GetSignerCounters())
	fmt.Fprintf(&out, "-- signatures: %d\n", len(instr.GetSignatures()))
	out.WriteString(EachLine.ReplaceAllString(methodStr, "-$1"))

	return out.String()
}

func (s smartc) GetContractRegistry() *ismartc.ContractRegistry {
	return nil
}

// ContractRegistry ...
type ContractRegistry struct {
}

// Search ...
func (c ContractRegistry) Search(what string) (func(in []byte) (ismartc.Contract, error), bool) {
	return nil, false
}

// GetDarcContractIDs ...
func (s smartc) GetDarcContractIDs() []string {
	return nil
}

// DUPLICATED
func (s smartc) RegisterGlobalContract(contractID string, f func(in []byte) (ismartc.Contract, error)) error {
	err := globalContractRegistry.register(contractID, f, false)
	return cothority.ErrorOrNil(err, "registration failed")
}

// DUPLICATED ...
func (s smartc) ContractConfigFromBytes(in []byte) (ismartc.Contract, error) {
	c := &contractConfig{}
	err := protobuf.Decode(in, &c.ChainConfig)

	if err != nil {
		return nil, xerrors.Errorf("decoding: %v", err)
	}
	return c, nil
}

// DUPLICATED
func (s smartc) ContractSecureDarcFromBytes(in []byte) (ismartc.Contract, error) {
	d, err := darc.NewFromProtobuf(in)
	if err != nil {
		return nil, xerrors.Errorf("darc decoding: %v", err)
	}
	c := &contractSecureDarc{Darc: *d}
	return c, nil
}

func (s smartc) GetContractDarcID() string {
	return "darc"
}

// GetISmartc ...
func GetISmartc() ismartc.ISmartc {
	return smartc{}
}

// FormatMethod returns the string representation of an instruction's method
// (ie. "Spawn", "Invoke", or "Delete"). This basic function simply calls
// "strconv.Quote" on the args of the method. It should be overrided by
// contracts that have more complex arguments. See the config contract for an
// example.
func (b BasicContract) FormatMethod(instr itransaction.Instruction) string {
	out := new(strings.Builder)

	instrType := instr.GetType2()
	if instr.IsSpawn(instrType) {
		out.WriteString("- Spawn:\n")
		fmt.Fprintf(out, "-- ContractID: %s\n", instr.GetContractID())
	} else if instr.IsInvoke(instrType) {
		out.WriteString("- Invoke:\n")
		fmt.Fprintf(out, "-- ContractID: %s\n", instr.GetContractID())
		command, err := instr.GetCommand()
		if err != nil {
			fmt.Fprintf(out, "-- Command: %s\n", command)
		} else {
			fmt.Fprintf(out, "-- Command: ERROR: %s\n", err.Error())
		}
	} else if instr.IsDelete(instrType) {
		out.WriteString("- Delete:\n")
		fmt.Fprintf(out, "-- ContractID: %s\n", instr.GetContractID())
	} else {
		out.WriteString("UNKOWN TYPE")
	}

	out.WriteString("-- Args:\n")
	for _, name := range instr.GetArgs().GetAllKeys() {
		fmt.Fprintf(out, "--- %s:\n", name)
		fmt.Fprintf(out, "---- %s\n", strconv.Quote(string(instr.GetArgs().Search(name))))
	}
	return out.String()
}

// ContractFn is the type signature of the instance factory functions which can be
// registered with the ByzCoin service.
type ContractFn func(in []byte) (ismartc.Contract, error)

// contractRegistry maps a contract ID with its constructor function. As soon
// as the first cloning happens, the registry will be locked and no new contract
// can be added for the global call.
type contractRegistry struct {
	registry map[string]func(in []byte) (ismartc.Contract, error)
	locked   bool
	sync.Mutex
}

// register tries to store the contract inside the registry. It will fail if the
// registry is locked and ignoreLock is set to false. It will also fail if the
// contract already exists.
// Because of backwards compatibility, the ignoreLock parameter can be set to
// true to register a contract after module initialization.
func (cr *contractRegistry) register(contractID string, f func(in []byte) (ismartc.Contract, error), ignoreLock bool) error {
	cr.Lock()
	if cr.locked && !ignoreLock {
		cr.Unlock()
		return xerrors.New("contract registry is locked")
	}

	_, exists := cr.registry[contractID]
	if exists {
		cr.Unlock()
		return xerrors.New("contract already registered")
	}

	cr.registry[contractID] = f
	cr.Unlock()
	return nil
}

// Search looks up the contract ID and returns the constructor function
// if it exists and nil otherwise.
func (cr *contractRegistry) Search(contractID string) (func(in []byte) (ismartc.Contract, error), bool) {
	cr.Lock()
	fn, exists := cr.registry[contractID]
	cr.Unlock()
	return fn, exists
}

// Clone returns a copy of the registry and locks the source so that
// static registration is not allowed anymore. This is to prevent
// registration of a contract at runtime and limit it only to the
// initialization phase.
func (cr *contractRegistry) clone() *contractRegistry {
	cr.Lock()
	cr.locked = true

	clone := newContractRegistry()
	// It is locked for outsiders but the package can manually update
	// the registry (e.g. tests)
	clone.locked = true
	for key, value := range cr.registry {
		clone.registry[key] = value
	}
	cr.Unlock()

	return clone
}

func newContractRegistry() *contractRegistry {
	return &contractRegistry{
		registry: make(map[string]func(in []byte) (ismartc.Contract, error)),
		locked:   false,
	}
}

var globalContractRegistry = newContractRegistry()

// RegisterGlobalContract stores the contract in the global registry. This should
// be called during module initialization as the registry will be locked down
// after the first cloning.
func RegisterGlobalContract(contractID string, f func(in []byte) (ismartc.Contract, error)) error {
	err := globalContractRegistry.register(contractID, f, false)
	return cothority.ErrorOrNil(err, "registration failed")
}

// RegisterContract stores the contract in the service registry which
// makes it only available to byzcoin.
//
// Deprecated: Use RegisterGlobalContract during the module initialization
// for a global access to the contract.
// func RegisterContract(s skipchain.GetService, contractID string, f ContractFn) error {
// 	scs := s.Service(transaction.ServiceName)
// 	if scs == nil {
// 		return xerrors.New("Didn't find our service: " + transaction.ServiceName)
// 	}

// 	err := scs.(*transaction.Service).contracts.register(contractID, f, true)
// 	return cothority.ErrorOrNil(err, "registration failed")
// }

// GetContractRegistry clones the global registry and returns a read-only one.
// Caution: calling this during the initialization will lock the registry.
func GetContractRegistry() ismartc.ReadOnlyContractRegistry {
	return globalContractRegistry.clone()
}

// BasicContract is a type that contracts may choose to embed in order to provide
// default implementations for the Contract interface.
type BasicContract struct{}

func notImpl(what string) error {
	return xerrors.Errorf("this contract does not implement %v", what)
}

// VerifyInstruction offers the default implementation of verifying an instruction. Types
// which embed BasicContract may choose to override this implementation.
// func (b BasicContract) VerifyInstruction(rst transaction.ReadOnlyStateTrie, inst transaction.Instruction, ctxHash []byte) error {
// 	return inst.VerifyWithOption(rst, ctxHash, &transaction.VerificationOptions{EvalAttr: b.MakeAttrInterpreters(rst, inst)})
// }

// VerifyDeferredInstruction is not implemented in a BasicContract. Types which
// embed BasicContract must override this method if they want to support
// deferred executions (using the Deferred contract).
// func (b BasicContract) VerifyDeferredInstruction(rst transaction.ReadOnlyStateTrie, inst transaction.Instruction, ctxHash []byte) error {
// 	return notImpl("VerifyDeferredInstruction")
// }

// MakeAttrInterpreters provides one default attribute verification which check
// whether the transaction is sent after a certain block index and before
// another block index.
// func (b BasicContract) MakeAttrInterpreters(rst transaction.ReadOnlyStateTrie, inst transaction.Instruction) darc.AttrInterpreters {
// 	cb := func(attr string) error {
// 		vals, err := url.ParseQuery(attr)
// 		if err != nil {
// 			return xerrors.Errorf("parsing query: %v", err)
// 		}
// 		beforeStr := vals.Get("before")
// 		afterStr := vals.Get("after")

// 		var before, after int

// 		if len(beforeStr) == 0 {
// 			// Set before to something higher than the current
// 			// index so that it always passes.
// 			before = rst.GetIndex() + 1
// 		} else {
// 			var err error
// 			before, err = strconv.Atoi(beforeStr)
// 			if err != nil {
// 				return xerrors.Errorf("atoi: %v")
// 			}
// 		}

// 		if len(afterStr) == 0 {
// 			after = -1
// 		} else {
// 			var err error
// 			after, err = strconv.Atoi(afterStr)
// 			if err != nil {
// 				return xerrors.Errorf("atoi: %v", err)
// 			}
// 		}

// 		if after < rst.GetIndex() && rst.GetIndex() < before {
// 			return nil
// 		}
// 		return xerrors.Errorf("the current block index is %d which does not fit in the interval (%d, %d)", rst.GetIndex(), after, before)
// 	}
// 	return darc.AttrInterpreters{"block": cb}
// }

// Spawn is not implmented in a BasicContract. Types which embed BasicContract
// must override this method if they support spawning.
func (b BasicContract) Spawn(itransaction.ReadOnlyStateTrie, itransaction.Instruction, itransaction.Transaction) (val []byte, err error) {
	err = notImpl("Spawn")
	return
}

// Invoke is not implmented in a BasicContract. Types which embed BasicContract
// must override this method if they support invoking.
func (b BasicContract) Invoke(itransaction.ReadOnlyStateTrie, itransaction.Instruction, itransaction.Transaction) (val []byte, err error) {
	err = notImpl("Invoke")
	return
}

// Delete is not implmented in a BasicContract. Types which embed BasicContract
// must override this method if they support deleting.
func (b BasicContract) Delete(itransaction.ReadOnlyStateTrie, itransaction.Instruction, itransaction.Transaction) (val []byte, err error) {
	err = notImpl("Delete")
	return
}

//
// Built-in contracts necessary for bootstrapping the ledger.
//  * Config
//  * SecureDarc
//

// ContractConfigID denotes a config-contract
const ContractConfigID = "config"

type instanceID struct {
	InstanceID [32]byte
}

func (i instanceID) GetInstanceID() [32]byte {
	return i.InstanceID
}

func (i instanceID) Slice() []byte {
	return i.InstanceID[:]
}

// ConfigInstanceID represents the 0-id of the configuration instance.
var ConfigInstanceID = instanceID{}

// ChainConfig ...
type ChainConfig struct {
	BlockInterval   time.Duration
	Roster          onet.Roster
	MaxBlockSize    int
	DarcContractIDs []string
}

type contractConfig struct {
	BasicContract
	ChainConfig
}

var _ ismartc.Contract = (*contractConfig)(nil)

// ContractConfigFromBytes ...
func ContractConfigFromBytes(in []byte) (ismartc.Contract, error) {
	c := &contractConfig{}
	err := protobuf.Decode(in, &c.ChainConfig)

	if err != nil {
		return nil, xerrors.Errorf("decoding: %v", err)
	}
	return c, nil
}

type darcContractIDs struct {
	IDs []string
}

// We need to override BasicContract.Verify because of the genesis config special case.
// func (c *contractConfig) VerifyInstruction(rst transaction.ReadOnlyStateTrie, inst transaction.Instruction, msg []byte) error {
// 	pr, err := rst.GetProof(ConfigInstanceID.Slice())
// 	if err != nil {
// 		return xerrors.Errorf("reading trie: %v", err)
// 	}
// 	ok, err := pr.Exists(ConfigInstanceID.Slice())
// 	if err != nil {
// 		return xerrors.Errorf("proof invalid: %v", err)
// 	}

// 	// The config does not exist yet, so this is a genesis config creation. No need/possiblity of verifying it.
// 	if !ok {
// 		return nil
// 	}

// 	err = inst.Verify(rst, msg)
// 	return cothority.ErrorOrNil(err, "instruction verification failed")
// }

// This is the same as the VerifyInstruction function, but it uses
// VerifyWithOption() instead of Verify(). We need to implement it in order to
// use deferred config contract.
// func (c *contractConfig) VerifyDeferredInstruction(rst transaction.ReadOnlyStateTrie, inst transaction.Instruction, msg []byte) error {
// 	pr, err := rst.GetProof(ConfigInstanceID.Slice())
// 	if err != nil {
// 		return xerrors.Errorf("reading trie: %v", err)
// 	}
// 	ok, err := pr.Exists(ConfigInstanceID.Slice())
// 	if err != nil {
// 		return xerrors.Errorf("invalid proof: %v", err)
// 	}

// 	// The config does not exist yet, so this is a genesis config creation. No need/possiblity of verifying it.
// 	if !ok {
// 		return nil
// 	}

// 	err = inst.VerifyWithOption(rst, msg, &transaction.VerificationOptions{IgnoreCounters: true})
// 	return cothority.ErrorOrNil(err, "instruction verification failed")
// }

// FormatMethod overrides the implementation from the BasicContract in order to
// proprely print "invoke:config.update_config"
// func (c *contractConfig) FormatMethod(instr itransaction.Instruction) string {
// 	out := new(strings.Builder)
// 	if instr.GetType() == transaction.InvokeType && instr.Invoke.Command == "update_config" {
// 		out.WriteString("- Invoke:\n")
// 		fmt.Fprintf(out, "-- ContractID: %s\n", instr.Invoke.ContractID)
// 		fmt.Fprintf(out, "-- Command: %s\n", instr.Invoke.Command)

// 		contractConfig := transaction.ChainConfig{}
// 		err := protobuf.Decode(instr.Invoke.Args.Search("config"), &contractConfig)
// 		if err != nil {
// 			return "[!!!] failed to decode contractConfig: " + err.Error()
// 		}

// 		out.WriteString("-- Args:\n")
// 		out.WriteString(transaction.EachLine.ReplaceAllString(contractConfig.String(), "--$1"))

// 		return out.String()
// 	}
// 	return c.BasicContract.FormatMethod(instr)
// }

// Spawn expects those arguments:
//   - darc           darc.Darc
//   - block_interval int64
//   - max_block_size int64
//   - roster         onet.Roster
//   - darc_contracts darcContractID
func (c *contractConfig) Spawn(rst itransaction.ReadOnlyStateTrie, inst itransaction.Instruction, trans itransaction.Transaction) ([]byte, error) {
	darcBuf := inst.GetArgs().Search("darc")
	d, err := darc.NewFromProtobuf(darcBuf)
	if err != nil {
		return nil, xerrors.Errorf("couldn't decode darc: %+v", err)
	}
	if d.Rules.Count() == 0 {
		return nil, xerrors.New("don't accept darc with empty rules")
	}
	if err = d.Verify(true); err != nil {
		return nil, xerrors.Errorf("couldn't verify darc: %v", err)
	}

	intervalBuf := inst.GetArgs().Search("block_interval")
	interval, _ := binary.Varint(intervalBuf)
	bsBuf := inst.GetArgs().Search("max_block_size")
	maxsz, _ := binary.Varint(bsBuf)

	rosterBuf := inst.GetArgs().Search("roster")
	roster := onet.Roster{}
	err = protobuf.DecodeWithConstructors(rosterBuf, &roster, network.DefaultConstructors(cothority.Suite))
	if err != nil {
		return nil, xerrors.Errorf("decoding roster: %v", err)
	}

	// create the config to be stored by state changes
	c.BlockInterval = time.Duration(interval)
	c.Roster = roster
	c.MaxBlockSize = int(maxsz)
	// if err = c.sanityCheck(nil); err != nil {
	// 	return nil, nil, xerrors.Errorf("sanity check: %v", err)
	// }

	// get the darc contracts
	darcContractIDsBuf := inst.GetArgs().Search("darc_contracts")
	dcIDs := darcContractIDs{}
	err = protobuf.Decode(darcContractIDsBuf, &dcIDs)
	if err != nil {
		return nil, xerrors.Errorf("decoding darc: %v", err)
	}
	c.DarcContractIDs = dcIDs.IDs

	configBuf, err := protobuf.Encode(c)
	if err != nil {
		return nil, xerrors.Errorf("encoding config: %v", err)
	}

	// id := d.GetBaseID()
	// sc := transaction.StateChanges{
	// 	transaction.NewStateChange(transaction.Create, ConfigInstanceID, ContractConfigID, configBuf, id),
	// 	transaction.NewStateChange(transaction.Create, transaction.NewInstanceID(id), ContractDarcID, darcBuf, id),
	// }
	return configBuf, nil
}

// Invoke offers the following functions:
//   - Invoke:update_config
//   - Invoke:view_change
//
// Invoke:update_config should have the following input argument:
//   - config ChainConfig
//
// Invoke:view_change sould have the following input arguments:
//   - newview viewchange.NewViewReq
//   - multisig []byte
func (c *contractConfig) Invoke(rst itransaction.ReadOnlyStateTrie, inst itransaction.Instruction, trans itransaction.Transaction) ([]byte, error) {
	// Find the darcID for this instance.
	var darcID darc.ID
	// _, _, _, darcID, err := rst.GetValues(inst.InstanceID.Slice())
	// if err != nil {
	// 	return nil, nil, xerrors.Errorf("reading trie: %v", err)
	// }

	// There are two situations where we need to change the roster:
	// 1. When it is initiated by the client(s) that holds the genesis
	//    signing key. In this case, we trust the client to do the right thing.
	// 2. During a view-change. In this case, we need to do additional
	//    validation to make sure a malicious node doesn't freely change the
	//    roster.
	command, err := inst.GetCommand()
	if err != nil {
		return nil, xerrors.Errorf("failed to get the command: %v", err)
	}
	switch command {
	case "update_config":
		configBuf := inst.GetArgs().Search("config")
		newConfig := ChainConfig{}
		err = protobuf.DecodeWithConstructors(configBuf, &newConfig, network.DefaultConstructors(cothority.Suite))
		if err != nil {
			return nil, xerrors.Errorf("decoding config: %v", err)
		}

		// var oldConfig ChainConfig
		// oldConfig, err = LoadConfigFromTrie(rst)
		// if err != nil {
		// 	return nil, xerrors.Errorf("reading trie: %v", err)
		// }
		// if err = newConfig.sanityCheck(oldConfig); err != nil {
		// 	return nil, nil, xerrors.Errorf("sanity check: %v", err)
		// }
		var val []byte
		val, _, _, _, err = rst.GetValues(darcID)
		if err != nil {
			return nil, xerrors.Errorf("reading trie: %v", err)
		}
		var genesisDarc *darc.Darc
		genesisDarc, err = darc.NewFromProtobuf(val)
		if err != nil {
			return nil, xerrors.Errorf("decoding darc: %v", err)
		}
		var rules []string
		for _, p := range newConfig.Roster.Publics() {
			rules = append(rules, "ed25519:"+p.String())
		}
		genesisDarc.Rules.UpdateRule("invoke:"+ContractConfigID+".view_change", expression.InitOrExpr(rules...))
		// var genesisBuf []byte
		// genesisBuf, err = genesisDarc.ToProto()
		// if err != nil {
		// 	return nil, nil, xerrors.Errorf("encoding darc: %v", err)
		// }
		// sc := transaction.StateChanges{
		// 	transaction.NewStateChange(transaction.Update, transaction.NewInstanceID(nil), ContractConfigID, configBuf, darcID),
		// 	transaction.NewStateChange(transaction.Update, transaction.NewInstanceID(darcID), ContractDarcID, genesisBuf, darcID),
		// }
		return configBuf, nil
	case "view_change":
		var req viewchange.NewViewReq
		err = protobuf.DecodeWithConstructors(inst.GetArgs().Search("newview"), &req, network.DefaultConstructors(cothority.Suite))
		if err != nil {
			return nil, xerrors.Errorf("decoding: %v", err)
		}
		// If everything is correctly signed, then we trust it, no need
		// to do additional verification.
		sigBuf := inst.GetArgs().Search("multisig")
		err = protocol.BlsSignature(sigBuf).Verify(trans.GetPairingSuite(), req.Hash(), req.Roster.ServicePublics(trans.GetServiceName()))
		if err != nil {
			return nil, xerrors.Errorf("invalid signature: %v", err)
		}

		config, err := LoadConfigFromTrie(rst)
		if err != nil {
			return nil, xerrors.Errorf("reading trie: %v", err)
		}
		config.Roster = req.Roster
		configBuf, err := protobuf.Encode(config)
		if err != nil {
			return nil, xerrors.Errorf("encoding: %v", err)
		}

		return configBuf, nil
	default:
		return nil, xerrors.New("invalid invoke command: " + command)
	}
}

// newInstanceID ...
func newInstanceID(in []byte) instanceID {
	i := instanceID{}
	copy(i.InstanceID[:], in)
	return i
}

// LoadConfigFromTrie loads the configuration data from the trie.
func LoadConfigFromTrie(st itransaction.ReadOnlyStateTrie) (*ChainConfig, error) {
	// Find the genesis-darc ID.
	val, _, contract, _, err := GetValueContract(st, newInstanceID(nil).Slice())
	if err != nil {
		return nil, xerrors.Errorf("reading trie: %w", err)
	}
	if string(contract) != ContractConfigID {
		return nil, xerrors.New("did not get " + ContractConfigID)
	}

	config := ChainConfig{}
	err = protobuf.DecodeWithConstructors(val, &config, network.DefaultConstructors(cothority.Suite))
	if err != nil {
		return nil, xerrors.Errorf("decoding config: %v", err)
	}

	return &config, nil
}

// GetValueContract gets all the information in an instance, an error is
// returned if the instance does not exist.
func GetValueContract(st itransaction.ReadOnlyStateTrie, key []byte) (value []byte, version uint64, contract string, darcID darc.ID, err error) {
	value, version, contract, darcID, err = st.GetValues(key)
	if err != nil {
		err = xerrors.Errorf("reading trie: %v", err)
		return
	}
	if value == nil {
		err = cothority.WrapError(xerrors.New("key not set"))
		return
	}
	return
}

// GetInstanceDarc ...
func GetInstanceDarc(c itransaction.ReadOnlyStateTrie, iid itransaction.InstanceID, darcContractIDs []string) (*darc.Darc, error) {
	// conver the string slice to a map
	m := make(map[string]bool)
	for _, id := range darcContractIDs {
		m[id] = true
	}

	// From instance ID, find the darcID that controls access to it.
	_, _, _, dID, err := c.GetValues(iid.Slice())
	if err != nil {
		return nil, xerrors.Errorf("reading trie: %v", err)
	}

	// Fetch the darc itself.
	value, _, contract, _, err := c.GetValues(dID)
	if err != nil {
		return nil, xerrors.Errorf("reading trie: %v", err)
	}

	if _, ok := m[string(contract)]; !ok {
		return nil, xerrors.Errorf("for instance %v, \"%v\" is not a contract ID that decodes to a DARC", iid, string(contract))
	}
	darc, err := darc.NewFromProtobuf(value)
	return darc, cothority.ErrorOrNil(err, "decoding darc")
}

// LoadDarcFromTrie loads a darc which should be stored in key.
func LoadDarcFromTrie(st itransaction.ReadOnlyStateTrie, key []byte) (*darc.Darc, error) {
	darcBuf, _, contract, _, err := st.GetValues(key)
	if err != nil {
		return nil, xerrors.Errorf("reading trie: %v", err)
	}
	config, err := LoadConfigFromTrie(st)
	if err != nil {
		return nil, xerrors.Errorf("reading trie: %v", err)
	}
	var ok bool
	for _, id := range config.DarcContractIDs {
		if contract == id {
			ok = true
		}
	}
	if !ok {
		return nil, xerrors.New("the contract \"" + contract + "\" is not in the set of DARC contracts")
	}
	d, err := darc.NewFromProtobuf(darcBuf)
	if err != nil {
		return nil, xerrors.Errorf("decoding darc: %v", err)
	}
	return d, nil
}
