package sharding

import (
	"github.com/0xharryriddle/DQNSB_Scheme/src/node"
)

type Shard struct {
	ID         uint64        `json:"id"`
	Validators []node.NodeID `json:"validators"`
}

type ShardingConfig struct {
	ShardCount          uint64             `json:"shard_count"`
	NodesPerShard       int                `json:"nodes_per_shard"`
	EpochLength         uint64             `json:"epoch_length"`
	CrossShardProtocol  CrossShardProtocol `json:"cross_shard_protocol"`
	ReshardingThreshold float64            `json:"resharding_threshold"`
}

// TODO: Implement CrossShardProtocol
type CrossShardProtocol string

// TODO: Implement CrossShardRef
type CrossShardRef struct{}
