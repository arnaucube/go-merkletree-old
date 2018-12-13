# go-merkletree [![Go Report Card](https://goreportcard.com/badge/github.com/arnaucube/go-merkletree)](https://goreportcard.com/report/github.com/arnaucube/go-merkletree) [![GoDoc](https://godoc.org/github.com/iden3/arnaucube/go-merkletree?status.svg)](https://godoc.org/github.com/iden3/arnaucube/go-merkletree)
Optimized MerkleTree implementation in Go.

The MerkleTree is optimized in the design and concepts, to have a faster and lighter MerkleTree, maintaining compatibility with a non optimized MerkleTree. In this way, the MerkleRoot of the optimized MerkleTree will be the same that the MerkleRoot of the non optimized MerkleTree.

This repo is holds the nostalgic (old) version of the MerkleTree implementation that we used in the past in iden3, as now has been substituted by a new specification.
