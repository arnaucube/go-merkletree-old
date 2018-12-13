package merkletree

import (
	"encoding/hex"
	"fmt"
	"strconv"
	"testing"
	"time"

	"github.com/dchest/uniuri"
	common3 "github.com/iden3/go-iden3/common"
	"github.com/stretchr/testify/assert"
	"github.com/syndtr/goleveldb/leveldb"
)

type testBase struct {
	Length    [4]byte
	Namespace Hash
	Type      Hash
	Version   uint32
}
type testLeaf struct {
	testBase
	extraIndex struct {
		Data []byte
	}
}

func parseTestLeafBytes(b []byte) testLeaf {
	var c testLeaf
	copy(c.testBase.Length[:], b[0:4])
	copy(c.testBase.Namespace[:], b[4:36])
	copy(c.testBase.Type[:], b[36:68])
	versionBytes := b[68:72]
	c.testBase.Version = common3.BytesToUint32(versionBytes)
	c.extraIndex.Data = b[72:]
	return c
}
func (c testLeaf) Bytes() (b []byte) {
	b = append(b, c.testBase.Length[:]...)
	b = append(b, c.testBase.Namespace[:]...)
	b = append(b, c.testBase.Type[:]...)
	versionBytes := common3.Uint32ToBytes(c.testBase.Version)
	b = append(b, versionBytes[:]...)
	b = append(b, c.extraIndex.Data[:]...)
	return b
}
func (c testLeaf) IndexLength() uint32 {
	return uint32(len(c.Bytes()))
}
func (c testLeaf) hi() Hash {
	h := HashBytes(c.Bytes())
	return h
}
func newTestLeaf(namespaceStr, typeStr string, data []byte) testLeaf {
	var c testLeaf
	c.testBase.Length = [4]byte{0x00, 0x00, 0x00, 0x48}
	c.testBase.Namespace = HashBytes([]byte(namespaceStr))
	c.testBase.Type = HashBytes([]byte(typeStr))
	c.testBase.Version = 0
	c.extraIndex.Data = data
	return c
}

type Fatalable interface {
	Fatal(args ...interface{})
}

func newTestingMerkle(f Fatalable, numLevels int) *MerkleTree {
	tim := time.Now().Unix()
	tstr := fmt.Sprint(tim)
	s := uniuri.New()
	db, err := leveldb.OpenFile("tmp/db"+s+"-"+tstr, nil)
	if err != nil {
		f.Fatal(err)
		return nil
	}
	// defer db.Close()
	mt, err := New(db, numLevels)
	if err != nil {
		f.Fatal(err)
		return nil
	}
	return mt
}

func TestNewMT(t *testing.T) {

	//create a new MT
	mt := newTestingMerkle(t, 140)
	defer mt.storage.Close()
	assert.Equal(t, "0x0000000000000000000000000000000000000000000000000000000000000000", mt.Root().Hex())
}

func TestAddLeaf(t *testing.T) {

	mt := newTestingMerkle(t, 140)
	defer mt.storage.Close()

	leaf := newTestLeaf("iden3.io", "typespec", []byte("c1"))
	assert.Equal(t, "0x939862c94ca9772fc9e2621df47128b1d4041b514e19edc969a92d8f0dae558f", leaf.hi().Hex())

	assert.Nil(t, mt.Add(leaf))
	assert.Equal(t, "0x9d3c407ff02c813cd474c0a6366b4f7c58bf417a38268f7a0d73a8bca2490b9b", mt.Root().Hex())
}

func TestAddLeafs(t *testing.T) {

	mt := newTestingMerkle(t, 140)
	defer mt.storage.Close()

	leaf := newTestLeaf("iden3.io", "typespec", []byte("c1"))
	assert.Equal(t, "0x939862c94ca9772fc9e2621df47128b1d4041b514e19edc969a92d8f0dae558f", leaf.hi().Hex())
	assert.Nil(t, mt.Add(leaf))

	assert.Nil(t, mt.Add(newTestLeaf("iden3.io2", "typespec2", []byte("c2"))))
	assert.Equal(t, "0xebae8fb483b48ba6c337136535198eb8bcf891daba40ac81e28958c09b9b229b", mt.Root().Hex())

	mt.Add(newTestLeaf("iden3.io3", "typespec3", []byte("c3")))
	mt.Add(newTestLeaf("iden3.io4", "typespec4", []byte("c4")))
	assert.Equal(t, "0xb4b51aa0c77a8e5ed0a099d7c11c7d2a9219ef241da84f0689da1f40a5f6ac31", mt.Root().Hex())
}

func TestAddLeafsCollision(t *testing.T) {

	mt := newTestingMerkle(t, 140)
	defer mt.storage.Close()

	leaf := newTestLeaf("iden3.io", "typespec", []byte("c1"))
	assert.Nil(t, mt.Add(leaf))

	root1 := mt.Root()
	assert.EqualError(t, mt.Add(leaf), ErrNodeAlreadyExists.Error())

	assert.Equal(t, root1.Hex(), mt.Root().Hex())
}

func TestAddLeafsDifferentOrders(t *testing.T) {

	mt1 := newTestingMerkle(t, 140)
	defer mt1.storage.Close()

	mt1.Add(newTestLeaf("iden3.io", "typespec", []byte("c1")))
	mt1.Add(newTestLeaf("iden3.io2", "typespec2", []byte("c2")))
	mt1.Add(newTestLeaf("iden3.io3", "typespec3", []byte("c3")))
	mt1.Add(newTestLeaf("iden3.io4", "typespec4", []byte("c4")))
	mt1.Add(newTestLeaf("iden3.io5", "typespec5", []byte("c5")))

	mt2 := newTestingMerkle(t, 140)
	defer mt2.storage.Close()

	mt2.Add(newTestLeaf("iden3.io3", "typespec3", []byte("c3")))
	mt2.Add(newTestLeaf("iden3.io2", "typespec2", []byte("c2")))
	mt2.Add(newTestLeaf("iden3.io", "typespec", []byte("c1")))
	mt2.Add(newTestLeaf("iden3.io4", "typespec4", []byte("c4")))
	mt2.Add(newTestLeaf("iden3.io5", "typespec5", []byte("c5")))

	assert.Equal(t, mt1.Root().Hex(), mt2.Root().Hex())
}
func TestBenchmarkAddingLeafs(t *testing.T) {

	mt := newTestingMerkle(t, 140)
	defer mt.storage.Close()

	start := time.Now()
	numToAdd := 1000
	for i := 0; i < numToAdd; i++ {
		leaf := newTestLeaf("iden3.io"+strconv.Itoa(i), "typespec"+strconv.Itoa(i), []byte("c"+strconv.Itoa(i)))
		mt.Add(leaf)
	}
	fmt.Print("time elapsed adding " + strconv.Itoa(numToAdd) + " leafs: ")
	fmt.Println(time.Since(start))
}
func BenchmarkAddingLeafs(b *testing.B) {

	mt := newTestingMerkle(b, 140)
	defer mt.storage.Close()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		leaf := newTestLeaf("iden3.io"+strconv.Itoa(i), "typespec"+strconv.Itoa(i), []byte("c"+strconv.Itoa(i)))
		if err := mt.Add(leaf); err != nil {
			b.Fatal(err)
		}
	}
}

func TestGenerateProof(t *testing.T) {
	mt := newTestingMerkle(t, 140)
	defer mt.storage.Close()

	mt.Add(newTestLeaf("iden3.io_3", "typespec_3", []byte("c3")))
	mt.Add(newTestLeaf("iden3.io_2", "typespec_2", []byte("c2")))

	leaf1 := newTestLeaf("iden3.io_1", "typespec_1", []byte("c1"))
	assert.Nil(t, mt.Add(leaf1))

	mp, err := mt.GenerateProof(parseTestLeafBytes(leaf1.Bytes()).hi())
	assert.Nil(t, err)

	mpHexExpected := "0000000000000000000000000000000000000000000000000000000000000002beb0fd6dcf18d37fe51cf34beacd4c524d9c039ef9da2a27ccd3e7edf662c39c"
	assert.Equal(t, mpHexExpected, hex.EncodeToString(mp))
}

func TestCheckProof(t *testing.T) {
	mt := newTestingMerkle(t, 140)
	defer mt.storage.Close()

	leaf1 := newTestLeaf("iden3.io_1", "typespec_1", []byte("c1"))
	assert.Nil(t, mt.Add(leaf1))

	leaf3 := newTestLeaf("iden3.io_3", "typespec_3", []byte("c3"))
	assert.Nil(t, mt.Add(leaf3))

	mp, err := mt.GenerateProof(parseTestLeafBytes(leaf1.Bytes()).hi())
	assert.Nil(t, err)
	verified := CheckProof(mt.Root(), mp, leaf1.hi(), HashBytes(leaf1.Bytes()), mt.NumLevels())
	assert.True(t, verified)

}

func TestProofOfEmpty(t *testing.T) { // proof of a non revocated leaf, prove that is empty the hi position of the leaf.version+1
	mt := newTestingMerkle(t, 140)
	defer mt.storage.Close()

	leaf1 := newTestLeaf("iden3.io_1", "typespec_1", []byte("c1"))
	// proof when there is nothing in the tree
	mp, err := mt.GenerateProof(leaf1.hi())
	assert.Nil(t, err)
	verified := CheckProof(mt.Root(), mp, leaf1.hi(), EmptyNodeValue, mt.NumLevels())
	assert.True(t, verified)

	// add the first leaf
	assert.Nil(t, mt.Add(leaf1))

	// proof when there is only one leaf in the tree
	leaf2 := newTestLeaf("iden3.io_2", "typespec_2", []byte("c2"))
	mp, err = mt.GenerateProof(leaf2.hi())
	assert.Nil(t, err)
	verified = CheckProof(mt.Root(), mp, leaf2.hi(), EmptyNodeValue, mt.NumLevels())
	assert.True(t, verified)

	// check that the value in Hi is Empty
	valueInPos, err := mt.GetValueInPos(leaf2.hi())
	assert.Nil(t, err)
	assert.Equal(t, EmptyNodeValue.Bytes(), valueInPos)
}

func DifferentNonExistenceProofs(t *testing.T) {
	mt1 := newTestingMerkle(t, 140)
	defer mt1.storage.Close()

	mt2 := newTestingMerkle(t, 140)
	defer mt2.storage.Close()

	leaf1 := newTestLeaf("iden3.io_1", "typespec_1", []byte("c1"))
	leaf2 := newTestLeaf("iden3.io_1", "typespec_1", []byte("c2"))

	assert.Nil(t, mt1.Add(leaf1))
	assert.Nil(t, mt2.Add(leaf2))

	leaf1.Version++
	leaf2.Version++

	np1, err := mt1.GenerateProof(leaf1.hi())
	assert.Nil(t, err)
	np2, err := mt2.GenerateProof(leaf2.hi())
	assert.Nil(t, err)

	assert.True(t, CheckProof(mt1.Root(), np1, leaf1.hi(), EmptyNodeValue, mt1.NumLevels()))
	assert.True(t, CheckProof(mt2.Root(), np2, leaf2.hi(), EmptyNodeValue, mt2.NumLevels()))

	assert.Equal(t, "0000000000000000000000000000000000000000000000000000000000000010a40617c8c3390736831d00b2003e2133353190f5d3b3a586cf829f0f2009aacc", hex.EncodeToString(np1))
	assert.Equal(t, "0000000000000000000000000000000000000000000000000000000000000001b274a34a3bd95915fe982a0163e3e0a2f79a371b8307661341f8914e22b313e1", hex.EncodeToString(np2))

}

func TestGetLeafInPos(t *testing.T) {
	mt := newTestingMerkle(t, 140)
	defer mt.storage.Close()

	for i := 0; i < 50; i++ {
		leaf := newTestLeaf("iden3.io"+strconv.Itoa(i), "typespec"+strconv.Itoa(i), []byte("c"+strconv.Itoa(i)))
		mt.Add(leaf)

	}
	leaf1 := newTestLeaf("iden3.io_x", "typespec_x", []byte("cx"))
	assert.Nil(t, mt.Add(leaf1))

	leaf := parseTestLeafBytes(leaf1.Bytes())
	leafInPosBytes, err := mt.GetValueInPos(leaf.hi())
	assert.Nil(t, err)
	assert.Equal(t, leaf1.Bytes(), leafInPosBytes)

	// empty value in position
	leaf2 := newTestLeaf("iden3.io_y", "typespec_y", []byte("cy"))
	leafInPosBytes, err = mt.GetValueInPos(leaf2.hi())
	assert.Nil(t, err)
	assert.Equal(t, EmptyNodeValue[:], leafInPosBytes)
}

type vt struct {
	v      []byte
	idxlen uint32
}

func (v vt) IndexLength() uint32 {
	return v.idxlen
}
func (v vt) Bytes() []byte {
	return v.v
}

func TestVector4(t *testing.T) {
	mt := newTestingMerkle(t, 4)
	defer mt.storage.Close()

	zeros := make([]byte, 32, 32)
	zeros[31] = 1 // to avoid adding Empty element
	assert.Nil(t, mt.Add(vt{zeros, uint32(1)}))
	v := vt{zeros, uint32(2)}
	assert.Nil(t, mt.Add(v))
	proof, _ := mt.GenerateProof(HashBytes(v.Bytes()[:v.IndexLength()]))
	assert.True(t, CheckProof(mt.Root(), proof, HashBytes(v.Bytes()[:v.IndexLength()]), HashBytes(v.Bytes()), mt.NumLevels()))
	assert.Equal(t, 4, mt.NumLevels())
	assert.Equal(t, "0000000000000000000000000000000000000000000000000000000000000001", hex.EncodeToString(v.Bytes()))
	assert.Equal(t, "0xc1b95ffbb999a6dd7a472a610a98891ffae95cc973d1d1e21acfdd68db830b51", mt.Root().Hex())
	assert.Equal(t, "00000000000000000000000000000000000000000000000000000000000000023cf025e4b4fc3ebe57374bf0e0c78ceb0009bdc4466a45174d80e8f508d1a4e3", hex.EncodeToString(proof))
}

func TestVector140(t *testing.T) {
	mt := newTestingMerkle(t, 140)
	defer mt.storage.Close()

	zeros := make([]byte, 32, 32)
	zeros[31] = 1 // to avoid adding Empty element
	for i := 1; i < len(zeros)-1; i++ {
		v := vt{zeros, uint32(i)}
		assert.Nil(t, mt.Add(v))
		proof, err := mt.GenerateProof(HashBytes(v.Bytes()[:v.IndexLength()]))
		assert.Nil(t, err)
		assert.True(t, CheckProof(mt.Root(), proof, HashBytes(v.Bytes()[:v.IndexLength()]), HashBytes(v.Bytes()), mt.NumLevels()))
		if i == len(zeros)-2 {
			assert.Equal(t, 140, mt.NumLevels())
			assert.Equal(t, uint32(30), v.IndexLength())
			assert.Equal(t, "0000000000000000000000000000000000000000000000000000000000000001", hex.EncodeToString(v.Bytes()))
			assert.Equal(t, "0x35f83288adf03bfb61d8d57fab9ed092da79833b58bbdbe9579b636753494ebd", mt.Root().Hex())
			assert.Equal(t, "000000000000000000000000000000000000000000000000000000000000001f0d1f363115f3333197a009b6674f46bba791308af220ad71515567702b3b44a2b540c1abad0ff81386a78b77e8907a56b7268d24513928ae83497adf4ad93a55e380267ead8305202da0640c1518e144dee87717c732b738fa182c6ef458defd6baf50022b01e3222715d4fca4c198e94536101f6ac314b3d261d3aaa0684395c1db60626e01c39fe4f69418055c2ebd70e0c07b6d9db5c4aed0a11ed2b6a773", hex.EncodeToString(proof))
		}
	}
}
