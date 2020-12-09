package main

import (
	"bytes"
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
// Tests should produced transactions that have already been broadcast to the network, tested by comparing the sha hashes of transactions that
// already exist in the chain with the generated tx


/*
	TODO:
	Issue segwit address from watcher
	Qredochain - build TX & Hash as determined by the source script type
	Watcher - sign hases, insert witness/script data & broadcast


 */



type input struct {
	wif string
	utxoScript	string
	txHash	string
	pubkey string
	utxoAmount int64
	index int
}

func Test_Mixed_P2PKH_input(t *testing.T) {
	fmt.Println("Mixed P2Pkh & Segwit")
	var utxos []input

	in1 := input{
		//address	2MxAAByddsP9VCGJcH28NMmkXz8xvSHKWhU
		wif:		"cPZXRr5CxtZ4pYHc2PdWTNpv8JiDRDrA3WSNLtgdSex77j1BDpjK",
		utxoScript: "a91435e360dcfe59bccdef3e91440e4083f1db03fef387",
		txHash:     "ff43f54e3d4bee9ca53c9212a37855a6cb08178f86ee9799acdd419269bf6ba9",
		pubkey:     "0253165B25EB3244E3905204E216BC5A0AF811C5A83141F4A4E258BC0302FE14D3",
		utxoAmount: int64(3232),
		index:      0,
	}

	in2 := input{
		//address	2MuerDacuzMeF4tJKvuY2exBpFmqaQkEQ8F
		wif:		"cPZXRr5CxtZ4pYHc2PdWTNpv8JiDRDrA3WSNLtgdSex7AiKafqTD",
		utxoScript: "a9141a680fb43832475b3072b7e0275bde1782b8dc5587",
		txHash:     "14dfab12129e23d2b7e6353aa3655704e85f97a3fad22519b7bc15cc0ad1317e",
		pubkey:     "023DA5062547B8A4D842FCA46733197B478DFBD3AF953862C12639B532B58D882D",
		utxoAmount: int64(2223),
		index:      0,
	}

	in3 := input{
		//address	mgVfzijYGVdff5pL2ZcNoEiUbyqm6RWWL2 1B11D8B8FB5E137A45844FF3E13EF3D6F0D03DE21C7150703AD43506B6734098
		wif:		"cNVKcCeqwcwRaE31TP5eUrZjM14WSRKC2Kz6u5tckqytkvSF7t6G",
		utxoScript: "76a9140aba1aae4a6b9e200a437af11780ab49d424cb5d88ac",
		txHash:     "4b76457b766a4fbd3728663e59f0ee4a18b914350b213f4eaab65ef12559f71f",
		pubkey:     "03CA0956C0D64C45FD7B2BE2E40993ACE5A5E0F79CCAA3F2156E1289D365CB0106",
		utxoAmount: int64(1111),
		index:      0,
	}
	utxos = append(utxos, in1)
	utxos = append(utxos, in2)
	utxos = append(utxos, in3)

	unsignedTX, hashes := Part1(t,utxos)
	//Watcher
	err := Part2(t, utxos, hashes, unsignedTX)
	assert.Nil(t, err,"Error should be nil")
    CheckTXID(t, unsignedTX, "60edf0738719567bb698d5de2d3ca71acb015163335a52c31f1c4e33b31f2b1b")
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
	err := Part2(t, utxos, hashes, unsignedTX)
	assert.Nil(t, err,"Error should be nil")
	CheckTXID(t, unsignedTX, "85c086da490aec5770c9d9fab407717c7f20636cdd5e620d5ce2ff3ddb29d38b")

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

	err := Part2(t, utxos, hashes, unsignedTX)
	assert.Nil(t, err,"Error should be nil")
	CheckTXID(t, unsignedTX, "c77eba6f7c817b5058383adbec0eba26980c3765f8adf2dceea99cd32d202061")
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
	err := Part2(t, utxos, hashes, unsignedTX)
	assert.Nil(t, err,"Error should be nil")
	CheckTXID(t, unsignedTX, "759820bb559cd0023523835374e7b692cc712b9bdc1473bc85d44db6fa6d7569")

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
	err := Part2(t, utxos, hashes, unsignedTX)
	assert.Nil(t, err,"Error should be nil")
	CheckTXID(t, unsignedTX, "cbac922dc53edb4188d8c051fcb385d13e558ca23ab3c06216f4293abb3a66ca")


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
func Part2(t *testing.T, utxos []input,hashes [][]uint8, unsignedTX *wire.MsgTx) (error){
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
	return  nil
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

func CheckTXID(t *testing.T, unsignedTX *wire.MsgTx, expectedTXID string) {
	//We need to strip out the winess data hashing twice to calculate the on chain TXID
	for i,_ := range  unsignedTX.TxIn {
		unsignedTX.TxIn[i].Witness=nil
	}
	buf := bytes.NewBuffer(make([]byte, 0, unsignedTX.SerializeSize()))
	_ = unsignedTX.Serialize(buf)
	txid := chainhash.DoubleHashH(buf.Bytes())
	assert.Equal(t, expectedTXID,txid.String())
}

