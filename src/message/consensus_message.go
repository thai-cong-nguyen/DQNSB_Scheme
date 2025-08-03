package message

import "github.com/0xharryriddle/DQNSB_Scheme/src/node"

type ConsensusMessage struct {
	Type      MessageType `json:"type"`
	Sender    node.NodeID `json:"sender"`
	Receiver  node.NodeID `json:"receiver"`
	Timestamp int64       `json:"timestamp"`
	Payload   []byte      `json:"payload"`
	Signature []byte      `json:"signature"`
}
