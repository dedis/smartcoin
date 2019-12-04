package smartc

import (
	"go.dedis.ch/onet/v3/log"
)

func init() {
	err := RegisterGlobalContract(ContractValueID, contractValueFromBytes)
	if err != nil {
		log.ErrFatal(err)
	}
	// err = byzcoin.RegisterGlobalContract(ContractCoinID, contractCoinFromBytes)
	// if err != nil {
	// 	log.ErrFatal(err)
	// }
	err = RegisterGlobalContract(ContractInsecureDarcID, contractInsecureDarcFromBytes)
	if err != nil {
		log.ErrFatal(err)
	}
}
