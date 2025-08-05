package node

type NodeID string

type Node struct {
	ID           NodeID
	IP           string
	Port         int64
	PublicKey    []byte
	ShardID      uint64
	IsValidator  bool
	Capabilities []string
}
