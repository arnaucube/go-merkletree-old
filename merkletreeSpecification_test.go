package merkletree

/*
This is just an example of basic tests for the (old) iden3-merkletree-specification.
The methods and variables names can be different.
*/

import (
	"strconv"
	"testing"

	"github.com/stretchr/testify/assert"
)

type testBytesLeaf struct {
	data        []byte
	indexLength uint32
}

func (c testBytesLeaf) Bytes() (b []byte) {
	return c.data
}
func (c testBytesLeaf) IndexLength() uint32 {
	return c.indexLength
}
func (c testBytesLeaf) Hi() Hash {
	h := HashBytes(c.Bytes()[:c.IndexLength()])
	return h
}
func newTestBytesLeaf(data string, indexLength uint32) testBytesLeaf {
	return testBytesLeaf{
		data:        []byte(data),
		indexLength: indexLength,
	}
}

// Test to check the iden3-merkletree-specification
func TestIden3MerkletreeSpecification(t *testing.T) {
	h := HashBytes([]byte("test")).Hex()
	assert.Equal(t, "0x9c22ff5f21f0b81b113e63f7db6da94fedef11b2119b4088b89664fb9a3cb658", h)

	h = HashBytes([]byte("authorizeksign")).Hex()
	assert.Equal(t, "0x353f867ef725411de05e3d4b0a01c37cf7ad24bcc213141a05ed7726d7932a1f", h)

	mt := newTestingMerkle(t, 140)
	defer mt.storage.Close()

	// empty tree
	assert.Equal(t, "0x0000000000000000000000000000000000000000000000000000000000000000", mt.Root().Hex())

	leafN := testBytesLeaf{
		data:        []byte{1, 2, 3, 4, 5},
		indexLength: 3,
	}
	assert.Nil(t, mt.Add(leafN))
	assert.Equal(t, "0xa0e72cc948119fcb71b413cf5ada12b2b825d5133299b20a6d9325ffc3e2fbf1", mt.Root().Hex())

	mt = newTestingMerkle(t, 140)
	defer mt.storage.Close()

	// add leaf
	leaf := testBytesLeaf{
		data:        []byte("this is a test leaf"),
		indexLength: 15,
	}
	assert.Nil(t, mt.Add(leaf))
	assert.Equal(t, "0xb4fdf8a653198f0e179ccb3af7e4fc09d76247f479d6cfc95cd92d6fda589f27", mt.Root().Hex())

	// proof with only one leaf in the MerkleTree
	proof, err := mt.GenerateProof(leaf.Hi())
	assert.Nil(t, err)
	assert.Equal(t, "0x0000000000000000000000000000000000000000000000000000000000000000", BytesToHex(proof))

	// add a second leaf
	leaf2 := testBytesLeaf{
		data:        []byte("this is a second test leaf"),
		indexLength: 15,
	}
	err = mt.Add(leaf2)
	assert.Nil(t, err)
	assert.Equal(t, "0x8ac95e9c8a6fbd40bb21de7895ee35f9c8f30ca029dbb0972c02344f49462e82", mt.Root().Hex())

	// proof of the second leaf, with two leafs in the MerkleTree
	proof2, err := mt.GenerateProof(leaf2.Hi())
	assert.Nil(t, err)
	assert.Equal(t, "0x0000000000000000000000000000000000000000000000000000000000000001fd8e1a60cdb23c0c7b2cf8462c99fafd905054dccb0ed75e7c8a7d6806749b6b", BytesToHex(proof2))

	// proof of emptyLeaf
	leaf3 := testBytesLeaf{
		data:        []byte("this is a third test leaf"),
		indexLength: 15,
	}
	proof3, err := mt.GenerateProof(leaf3.Hi())
	assert.Nil(t, err)
	assert.Equal(t, "0x000000000000000000000000000000000000000000000000000000000000000389741fa23da77c259781ad8f4331a5a7d793eef1db7e5200ddfc8e5f5ca7ce2bfd8e1a60cdb23c0c7b2cf8462c99fafd905054dccb0ed75e7c8a7d6806749b6b", BytesToHex(proof3))

	// getLeafByHi/GetValueInPos
	bytesInHi, err := mt.GetValueInPos(leaf2.Hi())
	assert.Nil(t, err)
	assert.Equal(t, leaf2.Bytes(), bytesInHi)

	// check proof
	rootBytes, err := HexToBytes("0x7d7c5e8f4b3bf434f3d9d223359c4415e2764dd38de2e025fbf986e976a7ed3d")
	assert.Nil(t, err)
	mp, err := HexToBytes("0x0000000000000000000000000000000000000000000000000000000000000002d45aada6eec346222eaa6b5d3a9260e08c9b62fcf63c72bc05df284de07e6a52")
	assert.Nil(t, err)
	hiBytes, err := HexToBytes("0x786677808ba77bdd9090a969f1ef2cbd1ac5aecd9e654f340500159219106878")
	assert.Nil(t, err)
	htBytes, err := HexToBytes("0x786677808ba77bdd9090a969f1ef2cbd1ac5aecd9e654f340500159219106878")
	assert.Nil(t, err)
	var root, hi, ht Hash
	copy(root[:], rootBytes)
	copy(hi[:], hiBytes)
	copy(ht[:], htBytes)
	verified := CheckProof(root, mp, hi, ht, 140)
	assert.True(t, verified)

	// check proof of empty
	rootBytes, err = HexToBytes("0x8f021d00c39dcd768974ddfe0d21f5d13f7215bea28db1f1cb29842b111332e7")
	assert.Nil(t, err)
	mp, err = HexToBytes("0x0000000000000000000000000000000000000000000000000000000000000004bf8e980d2ed328ae97f65c30c25520aeb53ff837579e392ea1464934c7c1feb9")
	assert.Nil(t, err)
	hiBytes, err = HexToBytes("0xa69792a4cff51f40b7a1f7ae596c6ded4aba241646a47538898f17f2a8dff647")
	assert.Nil(t, err)
	htBytes, err = HexToBytes("0x0000000000000000000000000000000000000000000000000000000000000000")
	assert.Nil(t, err)
	copy(root[:], rootBytes)
	copy(hi[:], hiBytes)
	copy(ht[:], htBytes)
	verified = CheckProof(root, mp, hi, ht, 140)
	assert.True(t, verified)

	// check the proof generated in the previous steps
	verified = CheckProof(mt.Root(), proof2, leaf2.Hi(), HashBytes(leaf2.Bytes()), 140)
	assert.True(t, verified)
	// check proof of no existence (emptyLeaf), as we are prooving an empty leaf, the Ht is an empty value (0x000...0)
	verified = CheckProof(mt.Root(), proof3, leaf3.Hi(), EmptyNodeValue, 140)
	assert.True(t, verified)

	// add leafs in different orders
	mt1 := newTestingMerkle(t, 140)
	defer mt1.storage.Close()

	mt1.Add(newTestBytesLeaf("0 this is a test leaf", 15))
	mt1.Add(newTestBytesLeaf("1 this is a test leaf", 15))
	mt1.Add(newTestBytesLeaf("2 this is a test leaf", 15))
	mt1.Add(newTestBytesLeaf("3 this is a test leaf", 15))
	mt1.Add(newTestBytesLeaf("4 this is a test leaf", 15))
	mt1.Add(newTestBytesLeaf("5 this is a test leaf", 15))
	// mt1.PrintFullMT()

	mt2 := newTestingMerkle(t, 140)
	defer mt2.storage.Close()

	mt2.Add(newTestBytesLeaf("2 this is a test leaf", 15))
	mt2.Add(newTestBytesLeaf("1 this is a test leaf", 15))
	mt2.Add(newTestBytesLeaf("0 this is a test leaf", 15))
	mt2.Add(newTestBytesLeaf("5 this is a test leaf", 15))
	mt2.Add(newTestBytesLeaf("3 this is a test leaf", 15))
	mt2.Add(newTestBytesLeaf("4 this is a test leaf", 15))

	assert.Equal(t, mt1.Root().Hex(), mt2.Root().Hex())
	assert.Equal(t, mt1.Root().Hex(), "0x264397f84da141b3134dcde1d7540d27a2bf0d787bbe8365d9ad5c9c18d3c621")

	// adding 1000 leafs
	mt1000 := newTestingMerkle(t, 140)
	defer mt.storage.Close()

	numToAdd := 1000
	for i := 0; i < numToAdd; i++ {
		leaf := newTestBytesLeaf(strconv.Itoa(i)+" this is a test leaf", 15)
		mt1000.Add(leaf)
	}
	assert.Equal(t, "0x6e2da580b2920cd78ed8d4e4bf41e209dfc99ef28bc19560042f0ac803e0d6f7", mt1000.Root().Hex())
}
