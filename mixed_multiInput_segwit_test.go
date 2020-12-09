package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"github.com/btcsuite/btcd/btcec"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
	"github.com/btcsuite/btcutil"
	"github.com/stretchr/testify/assert"
	"testing"
)

// Test_Segwit_External_Signing the hash & sign parts of the segwit transaction are buried inside the btsuite and are perforemed during
// txscript.WitnessSignature - the following test splits these operations into
// 1) Returns the hashes which will be used by the Qredoserver and put into the PBSettlementTransaction  / PBSettlementTransactionInput
// 2) These hashes are then signed by the MPCs in a separate process.

//Multi-input transactions
//Mixed input transactions
//Isolate required fields


type input struct {
	wif string
	utxoScript	string
	txHash	string
	pubkey string
	utxoAmount int64
	index int
}




func Test_Multiple_P2PKH_input(t *testing.T) {
	fmt.Println("Single P2Pkh")
	var utxos []input

	in1 := input{
		//address 	n4C7JDv8fTJSd5ix7jAfDrczsNng3fri9L
		wif:		"cURGtCeQL56gnmMxPxZm1Nonrmt2uLCeQpJj8NVw9PJWZ26E5Xnj",
		utxoScript: "76a914f8ba8148969d4226c9934f1eb2b80e290792969688ac",
		txHash:     "c6f337fd27130814ee3962a881bff63c17bbb5af791cd85bb4e0cf14d1b04978",
		pubkey:     "023C4B335C4900223BE4550FB32453FB1E45EE0D04E796E1037CE24042B4519BB8",
		utxoAmount: int64(5555),
		index:      0,
	}

	in2 := input{
		//address 	mq2ncLM2VX6EUbaVQAvqdnqr5ZenwpMVor
		wif:		"cP2RX2N2TFkFCPAJjtMaU7hKjetMvpag2vDEczHd6kTzuLA7HVmn",
		utxoScript: "76a914685d86c3d34b411f1193b21210543d1c86c366f988ac",
		txHash:     "d11b198a5cdf7abde9e22d0e69879d4c243dab7d10bce17048868879846f36cb",
		pubkey:     "02B6F7482F4BD62575EC29F0FF50D43139276B8A4711E021C1021CECADF0BCBEEB",
		utxoAmount: int64(6666),
		index:      0,
	}

	utxos = append(utxos, in1)//Qredochain
	utxos = append(utxos, in2)//Qredochain


	unsignedTX, hashes := Part1(t,utxos)

	//Watcher
	tx, err := Part2(t, utxos, hashes, unsignedTX)
	assert.Nil(t, err,"Error should be nil")


	fmt.Println("Transaction: ",hex.EncodeToString(tx))
	entireTXHash := sha256.Sum256(tx)
	entireTXHashHex := hex.EncodeToString(entireTXHash[:])

	assert.Equal(t, "19b14ce4b125dd391224a1871dbecc9d62caa73393c4dca47551cebabbd9373f", entireTXHashHex, "Invalid final TX")

}


func Test_Multiple_Segwit_input(t *testing.T) {
	fmt.Println("Multiple Segwit")
	var utxos []input

	//Multi
	in1 := input{
		//address 	2MukAGw8VL5yU8ns9GxRGeFRpztGTXhtKrW 2B11D8B8FB5E137A45844FF3E13EF3D6F0D03DE21C7150703AD43506B6734091
		wif:		"cP2RX2N2TFkFCPAJjtMaU7hKjetMvpag2vDEczHd6kTzuLA7HVmn",
		utxoScript: "a9141b69370e55fdecbfadaf394e29b1d118efff8ab087",
		txHash:     "c86a113cd2443e5ef521392a855fe5debdaaf774105881b6bc66a3c967262811",
		pubkey:     "02B6F7482F4BD62575EC29F0FF50D43139276B8A4711E021C1021CECADF0BCBEEB",
		utxoAmount: int64(2222),
		index:      0,
	}
	in2 := input{
		//address 	2NAHjPKRP1Cmxbqfm5V2PYzfhfaRZgne4H7 (3B11D8B8FB5E137A45844FF3E13EF3D6F0D03DE21C7150703AD43506B6734091)
		wif:		"cPZXRr5CxtZ4pYHc2PdWTNpv8JiDRDrA3WSNLtgdSex77EChPVHk",
		utxoScript: "a914baf3827eee4855a8cef6d1640c9326ffe9058df087",
		txHash:     "388b1520c40063ae29c9252b1bcdc3edd8d5402fdb150a26cb189dd95bd1018c",
		pubkey:     "03844BDB6D1CE87937513918BB54F00AA6B392AC781C73AF020C506DB237A1321A",
		utxoAmount: int64(3333),
		index:      0,
	}
	utxos = append(utxos, in1)
	utxos = append(utxos, in2)

	//Qredochain
	unsignedTX, hashes := Part1(t,utxos)

	//Watcher
	tx, err := Part2(t, utxos, hashes, unsignedTX)
	assert.Nil(t, err,"Error should be nil")


	fmt.Println("Transaction: ",hex.EncodeToString(tx))
	entireTXHash := sha256.Sum256(tx)
	entireTXHashHex := hex.EncodeToString(entireTXHash[:])

	assert.Equal(t, "5be492c3cda8e8f3f8ca57f2341817ae9509bcd52a6f92ecd76213dbb8b9b367", entireTXHashHex, "Invalid final TX")


}



func Test_Single_P2PKH_input(t *testing.T) {
	fmt.Println("Single P2Pkh")
	var utxos []input

	in1 := input{
		//address 	muwxb2YFzKTSSf1KZ6SC3DdEhBPLq3u1ij (cU2MCwHfJycARdk9MznxGsA4pxo7ZFBFQNfKyTcEB6XsM7U1nJnU)
		wif:		"cU2MCwHfJycARdk9MznxGsA4pxo7ZFBFQNfKyTcEB6XsM7U1nJnU",
		utxoScript: "76a9149e4c67807ad8186fc57b2b94222ff7374ca3c22488ac",
		txHash:     "4b1bb5078a71cde153bc81877f37aade23d2b5ff5d8974973c5188088b2392d3",
		pubkey:     "03F67329B01296D327883CE20D354E634B96C4A597B40E95B7852612ADFF946177",
		utxoAmount: int64(4444),
		index:      0,
	}
	utxos = append(utxos, in1)//Qredochain

	unsignedTX, hashes := Part1(t,utxos)

	//Watcher
	tx, err := Part2(t, utxos, hashes, unsignedTX)
	assert.Nil(t, err,"Error should be nil")


	fmt.Println("Transaction: ",hex.EncodeToString(tx))
	entireTXHash := sha256.Sum256(tx)
	entireTXHashHex := hex.EncodeToString(entireTXHash[:])

	assert.Equal(t, "08f64f293b98d75ee652bf3659d56c89dfbd01fb6979d5c357662059a98cc859", entireTXHashHex, "Invalid final TX")

}

func Test_Single_Segwit_input(t *testing.T) {
	fmt.Println("Single Segwit")
	var utxos []input

	//Multi
	in1 := input{
		//address 	2N4LyCq2xZnEfP5qm7GgvsqSosUMBBTq1GS (933a8EfDJfescwYXSbqvkvWF1SnLcQ9fcChrcSy1ii8SufbEzwj)
		wif:		"933a8EfDJfescwYXSbqvkvWF1SnLcQ9fcChrcSy1ii8SufbEzwj",
		utxoScript: "a91479bf89e019333a0a7caf926c2c69a656f4a0c67587",
		txHash:     "a14fe7a29f6e3077bc98fbf67963aa82b6544ac706c670033c4aef06f42256fe",
		pubkey:     "03F67329B01296D327883CE20D354E634B96C4A597B40E95B7852612ADFF946177",
		utxoAmount: int64(8000),
		index:      0,
	}

	utxos = append(utxos, in1)

	//Qredochain
	unsignedTX, hashes := Part1(t,utxos)

	//Watcher
	tx, err := Part2(t, utxos, hashes, unsignedTX)
	assert.Nil(t, err,"Error should be nil")


	fmt.Println("Transaction: ",hex.EncodeToString(tx))
	entireTXHash := sha256.Sum256(tx)
	entireTXHashHex := hex.EncodeToString(entireTXHash[:])

	assert.Equal(t, "02d0abfd03dfb181477853d6d09e9a3b52309d6ea6eb09b90ace569ad2915fe2", entireTXHashHex, "Invalid final TX")


}


//QredoChainWalletProcessing contains everything performed by a Qredo Node, before signing (especially hash generation)
func Part1(t *testing.T, utxos []input) (unsignedTX *wire.MsgTx,hashes [][]uint8) {
	chain := &chaincfg.TestNet3Params
	amountToSend := int64(1000)
	destinationAddress := "mjTabrhCExmGzAP3sYH43AVWJfCYf5D9WZ"

	//Qredochain

	//make  UnsignedTX
	//make  UnsignedTX
	var err error
	unsignedTX, err = UnsignedBuildTXMulti(destinationAddress, amountToSend,utxos, chain)
	assert.Nil(t, err, "Error", err)

	bufUnsigned := new(bytes.Buffer)
	_ = unsignedTX.Serialize(bufUnsigned)
	//entireTXHashUnsigned := sha256.Sum256(bufUnsigned.Bytes())
	//entireTXHashHexUnsigned := hex.EncodeToString(entireTXHashUnsigned[:])
	//assert.Equal(t, "e2f1e55ab2e2573d3d467766d00588ce99dce6d57d5ae5e4a22f9c1d42fab6aa", entireTXHashHexUnsigned, "Invalid unsigned TX")

	//Make Hashes
	hashes, err = HashBuildMulti(unsignedTX, utxos , txscript.SigHashAll, chain)
	assert.Nil(t, err, "Error", err)
	return  unsignedTX, hashes
}


func HashBuildMulti(unsignedTX *wire.MsgTx, utxos []input,  hashType txscript.SigHashType, chain *chaincfg.Params) ([][]uint8,  error) {
	sigHashes := txscript.NewTxSigHashes(unsignedTX)

	var hashres [][]uint8

	for ind,i := range utxos {
	_=ind
		pubKey, _ := hex.DecodeString(i.pubkey)
		pubKeyHash := btcutil.Hash160(pubKey)
		p2wkhAddr, err := btcutil.NewAddressWitnessPubKeyHash(pubKeyHash, chain)


		if err != nil {
			return  nil,err
		}
		witnessProgram, err := txscript.PayToAddrScript(p2wkhAddr)
		fmt.Println("WitnessProgram " + hex.EncodeToString(witnessProgram))

		//parsedScript, err := parseScript(subScript)
		//witness hashes
		scriptBytes, err := hex.DecodeString(i.utxoScript)
		var hash []byte
		if txscript.IsPayToScriptHash(scriptBytes) {
			hash, err = txscript.CalcWitnessSigHash(witnessProgram, sigHashes, hashType, unsignedTX, ind, i.utxoAmount)
		}else {
			script, _ := hex.DecodeString(i.utxoScript)
			hash, err = txscript.CalcSignatureHash(script, hashType, unsignedTX, ind)
		}


		hashres = append(hashres, hash)
		fmt.Println("HASH:" + hex.EncodeToString(hash))
	}
	return  hashres,nil
}

//WatcherProcessing signing the transaction hashes produced by QredoChainWalletProcessing, and assembling the final transaction for broadcast.
func Part2(t *testing.T, utxos []input,hashes [][]uint8, unsignedTX *wire.MsgTx) ([]byte, error){
	//setup

	chain := &chaincfg.TestNet3Params
	compress := true


	hashType := txscript.SigHashAll

	for ind, i := range utxos {
		wif, _ := btcutil.DecodeWIF(i.wif)
		pubkey := i.pubkey
		privKey := wif.PrivKey

		fmt.Println("Priv ", hex.EncodeToString(privKey.Serialize()))
		fmt.Println("Hash ", hex.EncodeToString(hashes[ind]))

		signature, err := privKey.Sign(hashes[ind])

		fmt.Println("sig ", hex.EncodeToString(signature.Serialize()))

		sig := append(signature.Serialize(), byte(hashType))
		pubKeyBytes, _ := hex.DecodeString(pubkey)
		pk, err := btcec.ParsePubKey(pubKeyBytes, btcec.S256())
		assert.Nil(t, err, "Error", err)
		var pkData []byte
		if compress {
			pkData = pk.SerializeCompressed()
		} else {
			pkData = pk.SerializeUncompressed()
		}

		scriptBytes, err := hex.DecodeString(i.utxoScript)
		if txscript.IsPayToScriptHash(scriptBytes) {
			witness := wire.TxWitness{sig, pkData}
			//finalize Transaction
			//make sigScript  - (again )
			pubKeyHash := btcutil.Hash160(pubKeyBytes)
			fmt.Println("pubKeyHash ", hex.EncodeToString(pubKeyHash))
			p2wkhAddr, err := btcutil.NewAddressWitnessPubKeyHash(pubKeyHash, chain)
			assert.Nil(t, err, "Error", err)
			witnessProgram, err := txscript.PayToAddrScript(p2wkhAddr)
			//assert.Equal(t, "00149e4c67807ad8186fc57b2b94222ff7374ca3c224", hex.EncodeToString(witnessProgram), "Invalid witness program")
			bldr := txscript.NewScriptBuilder()
			bldr.AddData(witnessProgram)
			sigScript, err := bldr.Script()

			unsignedTX.TxIn[ind].Witness = witness
			unsignedTX.TxIn[ind].SignatureScript = sigScript
		}else{
			sigScript, _ := txscript.NewScriptBuilder().AddData(sig).AddData(pkData).Script()
			unsignedTX.TxIn[ind].SignatureScript = sigScript
		}
	}
	//final check
	buf := new(bytes.Buffer)
	_ = unsignedTX.Serialize(buf)
	return buf.Bytes(), nil
}


func UnsignedBuildTXMulti(destination string, sendAmount int64, utxos []input, chain *chaincfg.Params) (*wire.MsgTx, error) {
	//Outgoing TX Address
	addr, _ := btcutil.DecodeAddress(destination, chain)
	p2shAddr, _ := txscript.PayToAddrScript(addr)
	utxOut := wire.NewTxOut(sendAmount, p2shAddr)

	var txins []*wire.TxIn
	for _,i := range utxos {
		incomingTXHash, _ := chainhash.NewHashFromStr(i.txHash)
		out := wire.OutPoint{
			Hash:  *incomingTXHash,
			Index: uint32(i.index),
		}
		in := &wire.TxIn{PreviousOutPoint: out}
		txins = append(txins, in)
	}
	outgoingTx := &wire.MsgTx{
		TxIn: txins,
		TxOut: []*wire.TxOut{utxOut},
	}
	return outgoingTx, nil

}