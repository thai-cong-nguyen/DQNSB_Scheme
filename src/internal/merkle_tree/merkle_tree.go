package internal

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"hash"
	"math/big"
)

type Item interface {
	CalculateHash() ([]byte, error)
	Equals(other Item) (bool, error)
}

type MerkleTree struct {
	Root         *Node
	merkleRoot   []byte
	Leafs        []*Node
	hashStrategy func() hash.Hash
	sort         bool
}

type Node struct {
	Tree      *MerkleTree
	Parent    *Node
	Left      *Node
	Right     *Node
	leaf      bool
	duplicate bool
	Hash      []byte
	item      Item
	sort      bool
}

func sortAppend(sort bool, a, b []byte) []byte {
	if !sort {
		return append(a, b...)
	}
	var aBig, bBig big.Int
	aBig.SetBytes(a)
	bBig.SetBytes(b)
	if aBig.Cmp(&bBig) == -1 {
		return append(a, b...)
	}
	return append(b, a...)
}

func buildWithItem(cs []Item, t *MerkleTree) (*Node, []*Node, error) {
	if len(cs) == 0 {
		return nil, nil, errors.New("error: cannot construct tree with no items")
	}
	var leafs []*Node
	for _, item := range cs {
		hash, err := item.CalculateHash()
		if err != nil {
			return nil, nil, err
		}

		leafs = append(leafs, &Node{
			Hash: hash,
			item: item,
			leaf: true,
			Tree: t,
		})
	}
	if len(leafs)%2 == 1 {
		duplicate := &Node{
			Hash:      leafs[len(leafs)-1].Hash,
			item:      leafs[len(leafs)-1].item,
			leaf:      true,
			duplicate: true,
			Tree:      t,
		}
		leafs = append(leafs, duplicate)
	}
	root, err := buildIntermediate(leafs, t)
	if err != nil {
		return nil, nil, err
	}

	return root, leafs, nil
}

func buildIntermediate(nl []*Node, t *MerkleTree) (*Node, error) {
	var nodes []*Node
	for i := 0; i < len(nl); i += 2 {
		h := t.hashStrategy()
		var left, right int = i, i + 1
		if i+1 == len(nl) {
			right = i
		}
		chash := sortAppend(t.sort, nl[left].Hash, nl[right].Hash)
		if _, err := h.Write(chash); err != nil {
			return nil, err
		}
		n := &Node{
			Left:  nl[left],
			Right: nl[right],
			Hash:  h.Sum(nil),
			Tree:  t,
		}
		nodes = append(nodes, n)
		nl[left].Parent = n
		nl[right].Parent = n
		if len(nl) == 2 {
			return n, nil
		}
	}
	return buildIntermediate(nodes, t)
}

func (m *MerkleTree) MerkleRoot() []byte {
	return m.merkleRoot
}

func NewMerkleTree(items []Item) (*MerkleTree, error) {
	var defaultHashStrategy = sha256.New

	tree := &MerkleTree{
		hashStrategy: defaultHashStrategy,
		sort:         false,
	}

	root, leafs, err := buildWithItem(items, tree)
	if err != nil {
		return nil, err
	}
	tree.Root = root
	tree.Leafs = leafs
	tree.merkleRoot = root.Hash
	return tree, nil
}

func (m *MerkleTree) String() string {
	s := "MerkleTree:\n"

	for _, leaf := range m.Leafs {
		s += fmt.Sprint(leaf) + "\n"
	}
	return s
}
