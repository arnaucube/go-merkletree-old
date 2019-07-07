package merkletree

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestNode(t *testing.T) {
	n := treeNode{
		ChildL: EmptyNodeValue,
		ChildR: EmptyNodeValue,
	}
	assert.Equal(t, "0xad3228b676f7d3cd4284a5443f17f1962b36e491b30a40b2405849e597ba5fb5", n.Ht().Hex())

}
