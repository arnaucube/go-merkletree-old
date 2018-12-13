package merkletree

import (
	"bytes"
	"errors"

	"github.com/syndtr/goleveldb/leveldb"
)

const (
	// EmptyNodeType indicates the type of an EmptyNodeValue Node
	EmptyNodeType = 00
	// NormalNodeType indicates the type of a middle Node
	normalNodeType = 01
	// FinalNodeType indicates the type of middle Node that is in an optimized branch, then in the value contains the value of the final leaf node of that branch
	finalNodeType = 02
	// ValueNodeType indicates the type of a value Node
	valueNodeType = 03
	// RootNodeType indicates the type of a root Node
	rootNodeType = 04
)

var (
	// ErrNodeAlreadyExists is an error that indicates that a node already exists in the merkletree database
	ErrNodeAlreadyExists = errors.New("node already exists")
	rootNodeValue        = HashBytes([]byte("root"))
	// EmptyNodeValue is a [32]byte EmptyNodeValue array, all to zero
	EmptyNodeValue       = Hash{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}
)

// Hash used in this tree, is the [32]byte keccak()
type Hash [32]byte

// Value is the interface of a generic leaf, a key value object stored in the leveldb
type Value interface {
	IndexLength() uint32 // returns the index length value
	Bytes() []byte       // returns the value in byte array representation
}

//MerkleTree struct with the main elements of the Merkle Tree
type MerkleTree struct {
	// sync.RWMutex
	storage   *leveldb.DB
	root      Hash
	numLevels int // Height of the Merkle Tree, number of levels
}

// New generates a new Merkle Tree
func New(storage *leveldb.DB, numLevels int) (*MerkleTree, error) {
	var mt MerkleTree
	mt.storage = storage
	mt.numLevels = numLevels
	var err error
	_, _, rootHash, err := mt.Get(rootNodeValue)
	if err != nil {
		mt.root = EmptyNodeValue
		err = mt.Insert(rootNodeValue, rootNodeType, 0, mt.root[:])
		if err != nil {
			return nil, err
		}
	}
	copy(mt.root[:], rootHash)
	return &mt, nil
}

// Root returns the merkletree.Root
func (mt *MerkleTree) Root() Hash {
	return mt.root
}

// NumLevels returns the merkletree.NumLevels
func (mt *MerkleTree) NumLevels() int {
	return mt.numLevels
}

// Add adds the leaf to the MT
func (mt *MerkleTree) Add(v Value) error {
	// add the leaf that we are adding
	mt.Insert(HashBytes(v.Bytes()), valueNodeType, v.IndexLength(), v.Bytes())

	hi := HashBytes(v.Bytes()[:v.IndexLength()])
	path := getPath(mt.numLevels, hi)

	nodeHash := mt.root
	var siblings []Hash
	for i := mt.numLevels - 2; i >= 0; i-- {
		nodeType, indexLength, nodeBytes, err := mt.Get(nodeHash)
		if err != nil {
			return err
		}
		if nodeType == byte(finalNodeType) {
			hiChild := HashBytes(nodeBytes[:indexLength])
			pathChild := getPath(mt.numLevels, hiChild)
			posDiff := comparePaths(pathChild, path)
			if posDiff == -1 {
				return ErrNodeAlreadyExists
			}
			finalNode1Hash := calcHashFromLeafAndLevel(posDiff, pathChild, HashBytes(nodeBytes))
			mt.Insert(finalNode1Hash, finalNodeType, indexLength, nodeBytes)
			finalNode2Hash := calcHashFromLeafAndLevel(posDiff, path, HashBytes(v.Bytes()))
			mt.Insert(finalNode2Hash, finalNodeType, v.IndexLength(), v.Bytes())
			// now the parent
			var parentNode treeNode
			if path[posDiff] {
				parentNode = treeNode{
					ChildL: finalNode1Hash,
					ChildR: finalNode2Hash,
				}
			} else {
				parentNode = treeNode{
					ChildL: finalNode2Hash,
					ChildR: finalNode1Hash,
				}
			}
			siblings = append(siblings, getEmptiesBetweenIAndPosHash(mt, i, posDiff+1)...)
			if mt.root, err = mt.replaceLeaf(siblings, path[posDiff+1:], parentNode.Ht(), normalNodeType, 0, parentNode.Bytes()); err != nil {
				return err
			}
			mt.Insert(rootNodeValue, rootNodeType, 0, mt.root[:])
			return nil
		}
		node := parseNodeBytes(nodeBytes)
		var sibling Hash
		if !path[i] {
			nodeHash = node.ChildL
			sibling = node.ChildR
		} else {
			nodeHash = node.ChildR
			sibling = node.ChildL
		}
		siblings = append(siblings, sibling)

		if bytes.Equal(nodeHash[:], EmptyNodeValue[:]) {
			// if the node is EmptyNodeValue, the leaf data will go directly at that height, as a Final Node
			if i == mt.numLevels-2 && bytes.Equal(siblings[len(siblings)-1][:], EmptyNodeValue[:]) {
				// if the pt node is the unique in the tree, just put it into the root node
				// this means to be in i==mt.NumLevels-2 && nodeHash==EmptyNodeValue
				finalNodeHash := calcHashFromLeafAndLevel(i+1, path, HashBytes(v.Bytes()))
				mt.Insert(finalNodeHash, finalNodeType, v.IndexLength(), v.Bytes())
				mt.root = finalNodeHash
				mt.Insert(rootNodeValue, rootNodeType, 0, mt.root[:])
				return nil
			}
			finalNodeHash := calcHashFromLeafAndLevel(i, path, HashBytes(v.Bytes()))
			if mt.root, err = mt.replaceLeaf(siblings, path[i:], finalNodeHash, finalNodeType, v.IndexLength(), v.Bytes()); err != nil {
				return err
			}
			mt.Insert(rootNodeValue, rootNodeType, 0, mt.root[:])
			return nil
		}
	}

	var err error
	mt.root, err = mt.replaceLeaf(siblings, path, HashBytes(v.Bytes()), valueNodeType, v.IndexLength(), v.Bytes())
	if err != nil {
		return err
	}
	mt.Insert(rootNodeValue, rootNodeType, 0, mt.root[:])
	return nil
}

// GenerateProof generates the Merkle Proof from a given leafHash for the current root
func (mt *MerkleTree) GenerateProof(hi Hash) ([]byte, error) {
	var empties [32]byte

	path := getPath(mt.numLevels, hi)
	var siblings []Hash
	nodeHash := mt.root

	for level := 0; level < mt.numLevels-1; level++ {
		nodeType, indexLength, nodeBytes, err := mt.Get(nodeHash)
		if err != nil {
			return nil, err
		}
		if nodeType == byte(finalNodeType) {
			realValueInPos, err := mt.GetValueInPos(hi)
			if err != nil {
				return nil, err
			}
			if bytes.Equal(realValueInPos[:], EmptyNodeValue[:]) {
				// go until the path is different, then get the nodes between this FinalNode and the node in the diffPath, they will be the siblings of the merkle proof
				leafHi := HashBytes(nodeBytes[:indexLength]) // hi of element that was in the end of the branch (the finalNode)
				pathChild := getPath(mt.numLevels, leafHi)

				// get the position where the path is different
				posDiff := comparePaths(pathChild, path)
				if posDiff == -1 {
					return nil, ErrNodeAlreadyExists
				}

				if posDiff != mt.NumLevels()-1-level {
					sibling := calcHashFromLeafAndLevel(posDiff, pathChild, HashBytes(nodeBytes))
					setbitmap(empties[:], uint(mt.NumLevels()-2-posDiff))
					siblings = append([]Hash{sibling}, siblings...)
				}

			}
			break
		}
		node := parseNodeBytes(nodeBytes)

		var sibling Hash
		if !path[mt.numLevels-level-2] {
			nodeHash = node.ChildL
			sibling = node.ChildR
		} else {
			nodeHash = node.ChildR
			sibling = node.ChildL
		}
		if !bytes.Equal(sibling[:], EmptyNodeValue[:]) {
			setbitmap(empties[:], uint(level))
			siblings = append([]Hash{sibling}, siblings...)
		}
	}
	// merge empties and siblings
	var mp []byte
	mp = append(mp, empties[:]...)
	for k := range siblings {
		mp = append(mp, siblings[k][:]...)
	}
	return mp, nil
}

// GetValueInPos returns the merkletree value in the position of the Hash of the Index (Hi)
func (mt *MerkleTree) GetValueInPos(hi Hash) ([]byte, error) {
	path := getPath(mt.numLevels, hi)
	nodeHash := mt.root
	for i := mt.numLevels - 2; i >= 0; i-- {
		nodeType, indexLength, nodeBytes, err := mt.Get(nodeHash)
		if err != nil {
			return nodeBytes, err
		}
		if nodeType == byte(finalNodeType) {
			// check if nodeBytes path is different of hi
			index := nodeBytes[:indexLength]
			hi := HashBytes(index)
			nodePath := getPath(mt.numLevels, hi)
			posDiff := comparePaths(path, nodePath)
			// if is different, return an EmptyNodeValue, else return the nodeBytes
			if posDiff != -1 {
				return EmptyNodeValue[:], nil
			}
			return nodeBytes, nil
		}
		node := parseNodeBytes(nodeBytes)
		if !path[i] {
			nodeHash = node.ChildL
		} else {
			nodeHash = node.ChildR
		}
	}
	_, _, valueBytes, err := mt.Get(nodeHash)
	if err != nil {
		return valueBytes, err
	}
	return valueBytes, nil
}

func calcHashFromLeafAndLevel(untilLevel int, path []bool, leafHash Hash) Hash {
	nodeCurrLevel := leafHash
	for i := 0; i < untilLevel; i++ {
		if path[i] {
			node := treeNode{
				ChildL: EmptyNodeValue,
				ChildR: nodeCurrLevel,
			}
			nodeCurrLevel = node.Ht()
		} else {
			node := treeNode{
				ChildL: nodeCurrLevel,
				ChildR: EmptyNodeValue,
			}
			nodeCurrLevel = node.Ht()
		}
	}
	return nodeCurrLevel
}

func (mt *MerkleTree) replaceLeaf(siblings []Hash, path []bool, newLeafHash Hash, nodetype byte, indexLength uint32, newLeafValue []byte) (Hash, error) {
	// add the new leaf
	mt.Insert(newLeafHash, nodetype, indexLength, newLeafValue)
	currNode := newLeafHash
	// here the path is only the path[posDiff+1]
	for i := 0; i < len(siblings); i++ {
		if !path[i] {
			node := treeNode{
				ChildL: currNode,
				ChildR: siblings[len(siblings)-1-i],
			}
			mt.Insert(node.Ht(), normalNodeType, 0, node.Bytes())
			currNode = node.Ht()
		} else {

			node := treeNode{
				ChildL: siblings[len(siblings)-1-i],
				ChildR: currNode,
			}
			mt.Insert(node.Ht(), normalNodeType, 0, node.Bytes())
			currNode = node.Ht()
		}
	}

	return currNode, nil // currNode = root
}

// CheckProof validates the Merkle Proof for the leafHash and root
func CheckProof(root Hash, proof []byte, hi Hash, ht Hash, numLevels int) bool {
	var empties [32]byte
	copy(empties[:], proof[:len(empties)])
	hashLen := len(EmptyNodeValue)

	var siblings []Hash
	for i := len(empties); i < len(proof); i += hashLen {
		var siblingHash Hash
		copy(siblingHash[:], proof[i:i+hashLen])
		siblings = append(siblings, siblingHash)
	}

	path := getPath(numLevels, hi)
	nodeHash := ht
	siblingUsedPos := 0

	for level := numLevels - 2; level >= 0; level-- {
		var sibling Hash
		if testbitmap(empties[:], uint(level)) {
			sibling = siblings[siblingUsedPos]
			siblingUsedPos++
		} else {
			sibling = EmptyNodeValue
		}
		// calculate the nodeHash with the current nodeHash and the sibling
		var node treeNode
		if path[numLevels-level-2] {
			node = treeNode{
				ChildL: sibling,
				ChildR: nodeHash,
			}
		} else {
			node = treeNode{
				ChildL: nodeHash,
				ChildR: sibling,
			}
		}
		// if both childs are EmptyNodeValue, the parent will be EmptyNodeValue
		if bytes.Equal(nodeHash[:], EmptyNodeValue[:]) && bytes.Equal(sibling[:], EmptyNodeValue[:]) {
			nodeHash = EmptyNodeValue
		} else {
			nodeHash = node.Ht()
		}
	}
	return bytes.Equal(nodeHash[:], root[:])
}
