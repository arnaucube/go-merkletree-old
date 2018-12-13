package merkletree

import (
	"bytes"

	"github.com/fatih/color"
	common3 "github.com/iden3/go-iden3/common"
)

func (mt *MerkleTree) Insert(key Hash, nodeType byte, indexLength uint32, nodeBytes []byte) error {
	// add nodetype at the first byte of the value
	var value []byte
	value = append(value, nodeType)
	indexLengthBytes := common3.Uint32ToBytes(indexLength)
	value = append(value, indexLengthBytes[:]...)
	value = append(value, nodeBytes[:]...)

	err := mt.storage.Put(key[:], value, nil)
	if err != nil {
		color.Red(err.Error())
		return err
	}
	return nil
}

func (mt *MerkleTree) Get(key Hash) (byte, uint32, []byte, error) {
	if bytes.Equal(key[:], EmptyNodeValue[:]) {
		return 0, 0, EmptyNodeValue[:], nil
	}

	value, err := mt.storage.Get(key[:], nil)
	if err != nil {
		return 0, 0, EmptyNodeValue[:], err
	}

	// get nodetype of the first byte of the value
	nodeType := value[0]
	indexLength := common3.BytesToUint32(value[1:5])
	nodeBytes := value[5:]
	return nodeType, indexLength, nodeBytes, err
}
