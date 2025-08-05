package internal

import (
	"bytes"
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

func (n *Node) verifyNode(sort bool) ([]byte, error) {
	if n.leaf {
		return n.item.CalculateHash()
	}

	rightNodeBytes, err := n.Right.verifyNode(sort)

	if err != nil {
		return nil, err
	}

	leftNodeBytes, err := n.Left.verifyNode(sort)
	if err != nil {
		return nil, err
	}

	hash := n.Tree.hashStrategy()
	if _, err := hash.Write(sortAppend(sort, leftNodeBytes, rightNodeBytes)); err != nil {
		return nil, err
	}

	return hash.Sum(nil), nil
}

func (n *Node) calculateNodeHash(sort bool) ([]byte, error) {
	if n.leaf {
		return n.item.CalculateHash()
	}

	hash := n.Tree.hashStrategy()

	if _, err := hash.Write(sortAppend(sort, n.Left.Hash, n.Right.Hash)); err != nil {
		return nil, err
	}

	return hash.Sum(nil), nil
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

func NewMerkleTreeWithHashStrategy(items []Item, hashStrategy func() hash.Hash) (*MerkleTree, error) {
	tree := &MerkleTree{
		hashStrategy: hashStrategy,
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

func NewMerkleTreeWithHashStrategySorted(items []Item, hashStrategy func() hash.Hash) (*MerkleTree, error) {
	tree := &MerkleTree{
		hashStrategy: hashStrategy,
		sort:         true,
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

func (m *MerkleTree) GetMerklePath(item Item) ([][]byte, []int64, error) {
	for _, current := range m.Leafs {
		equal, err := current.item.Equals(item)
		if err != nil {
			return nil, nil, err
		}
		if equal {
			currentParent := current.Parent
			var merklePath [][]byte
			var index []int64
			for currentParent != nil {
				if bytes.Equal(current.Left.Hash, current.Hash) {
					merklePath = append(merklePath, current.Right.Hash)
					index = append(index, 1)
				} else {
					merklePath = append(merklePath, current.Left.Hash)
					index = append(index, 0)
				}
				current = currentParent
				currentParent = currentParent.Parent
			}
			return merklePath, index, nil
		}
	}
	return nil, nil, nil
}

func buildWithItem(items []Item, t *MerkleTree) (*Node, []*Node, error) {
	if len(items) == 0 {
		return nil, nil, errors.New("error: cannot construct tree with no items")
	}
	var leafs []*Node
	for _, item := range items {
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

func (m *MerkleTree) RebuildTree() error {
	var items []Item
	for _, item := range m.Leafs {
		items = append(items, item.item)
	}

	root, leafs, err := buildWithItem(items, m)
	if err != nil {
		return err
	}
	m.Root = root
	m.Leafs = leafs
	m.merkleRoot = root.Hash
	return nil
}

func (m *MerkleTree) RebuildTreeWith(items []Item) error {
	root, leafs, err := buildWithItem(items, m)
	if err != nil {
		return err
	}
	m.Root = root
	m.Leafs = leafs
	m.merkleRoot = root.Hash
	return nil
}

func (m *MerkleTree) VerifyTree() (bool, error) {
	calculatedMerkleRoot, err := m.Root.verifyNode(m.sort)
	if err != nil {
		return false, err
	}
	if bytes.Equal(m.merkleRoot, calculatedMerkleRoot) {
		return true, nil
	}
	return false, nil
}

func (m *MerkleTree) VerifyItem(item Item) (bool, error) {
	for _, leaf := range m.Leafs {
		equal, err := leaf.item.Equals(item)
		if err != nil {
			return false, err
		}
		if equal {
			currentParent := leaf.Parent
			for currentParent != nil {
				hash := m.hashStrategy()
				rightNodeBytes, err := currentParent.Right.calculateNodeHash(m.sort)
				if err != nil {
					return false, err
				}
				leftNodeBytes, err := currentParent.Left.calculateNodeHash(m.sort)
				if err != nil {
					return false, err
				}
				if _, err := hash.Write(sortAppend(m.sort, leftNodeBytes, rightNodeBytes)); err != nil {
					return false, err
				}
				if !bytes.Equal(hash.Sum(nil), currentParent.Hash) {
					return false, nil
				}
				currentParent = currentParent.Parent
			}
			return true, nil
		}
	}
	return false, nil
}

func (m *MerkleTree) String() string {
	s := "MerkleTree:\n"

	for _, leaf := range m.Leafs {
		s += fmt.Sprint(leaf) + "\n"
	}
	return s
}

func (n *Node) String() string {
	return fmt.Sprintf("Node{Hash: %x, Leaf: %t, Duplicate: %t, Item: %v}", n.Hash, n.leaf, n.duplicate, n.item)
}
