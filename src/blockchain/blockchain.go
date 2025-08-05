package blockchain

import (
	"github.com/0xharryriddle/DQNSB_Scheme/src/node"
	"github.com/0xharryriddle/DQNSB_Scheme/src/sharding"
)

type BlockHeader struct{}

type Block struct {
	Header       BlockHeader
	Transactions []string
	ShardID      int
	ProposerID   node.NodeID
	Signature    []byte
	StateRoot    []byte
	ReceiptRoot  []byte
}

type Transaction struct {
	ID            []byte
	Sender        []byte
	Receiver      []byte
	Amount        uint64
	Fee           uint64
	Data          []byte
	Signature     []byte
	Nonce         uint64
	ShardID       uint64
	CrossShardRef *sharding.CrossShardRef
}
