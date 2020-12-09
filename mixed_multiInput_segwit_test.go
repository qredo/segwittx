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






func Test_Mixed_multi_input(t *testing.T) {
	fmt.Println("MULTI")
	var utxos []input

	//in1 := input{
	//	//address 	muwxb2YFzKTSSf1KZ6SC3DdEhBPLq3u1ij (cU2MCwHfJycARdk9MznxGsA4pxo7ZFBFQNfKyTcEB6XsM7U1nJnU)
	//	wif:		"cU2MCwHfJycARdk9MznxGsA4pxo7ZFBFQNfKyTcEB6XsM7U1nJnU",
	//	utxoScript: "76a9149e4c67807ad8186fc57b2b94222ff7374ca3c22488ac",
	//	txHash:     "4b1bb5078a71cde153bc81877f37aade23d2b5ff5d8974973c5188088b2392d3",
	//	pubkey:     "03F67329B01296D327883CE20D354E634B96C4A597B40E95B7852612ADFF946177",
	//	utxoAmount: int64(4444),
	//	index:      0,
	//}
	//utxos = append(utxos, in1)


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

	//in2 := input{
	//	//address 	2N4LyCq2xZnEfP5qm7GgvsqSosUMBBTq1GS (933a8EfDJfescwYXSbqvkvWF1SnLcQ9fcChrcSy1ii8SufbEzwj)
	//	wif: "933a8EfDJfescwYXSbqvkvWF1SnLcQ9fcChrcSy1ii8SufbEzwj",
	//	utxoScript: "76a914dd5b3889cb25577c192f66cd2e897e51eba31c9c88ac",
	//	txHash:     "526c3b22c6f5d2679054ff81a2864f73ce44bbaa4638f811b95e68006035cd85",
	//	pubkey:     "0252403761EE1F9AC08FA76E1269F360521808534A52EC7DF43FC4CC3BCD1D4BE3",
	//	utxoAmount: int64(6000),
	//	index:      0,
	//}
	utxos = append(utxos, in1)
	//utxos = append(utxos, in2)

	//Qredochain
	unsignedTX, hashes := Part1(t,utxos)

	//Watcher
	Part2(t, utxos, hashes, unsignedTX)

}

type input struct {
	wif string
	utxoScript	string
	txHash	string
	pubkey string
	utxoAmount int64
	index int
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
	entireTXHashUnsigned := sha256.Sum256(bufUnsigned.Bytes())
	entireTXHashHexUnsigned := hex.EncodeToString(entireTXHashUnsigned[:])
	assert.Equal(t, "e2f1e55ab2e2573d3d467766d00588ce99dce6d57d5ae5e4a22f9c1d42fab6aa", entireTXHashHexUnsigned, "Invalid unsigned TX")

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
		hash, err := txscript.CalcWitnessSigHash(witnessProgram, sigHashes, hashType, unsignedTX, i.index, i.utxoAmount)

		//p2pkh hashes
		//script, _ := hex.DecodeString(i.utxoScript)
		//hash, err = txscript.CalcSignatureHash(script, hashType, unsignedTX, ind)


		hashres = append(hashres, hash)
		fmt.Println("HASH:" + hex.EncodeToString(hash))
	}
	return  hashres,nil
}

//WatcherProcessing signing the transaction hashes produced by QredoChainWalletProcessing, and assembling the final transaction for broadcast.
func Part2(t *testing.T, utxos []input,hashes [][]uint8, unsignedTX *wire.MsgTx) {
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




		//sigScript, _ := txscript.NewScriptBuilder().AddData(sig).AddData(pkData).Script()
		//unsignedTX.TxIn[ind].SignatureScript = sigScript



	}

	//final check
	buf := new(bytes.Buffer)
	_ = unsignedTX.Serialize(buf)

	fmt.Println("Transaction: ",hex.EncodeToString(buf.Bytes()))
	entireTXHash := sha256.Sum256(buf.Bytes())
	entireTXHashHex := hex.EncodeToString(entireTXHash[:])

	assert.Equal(t, "46efa28e9ba27e89514de5a5ae8b7072955bbe9e240906d4727f333d5b4ba152", entireTXHashHex, "Invalid final TX")
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