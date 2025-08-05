package message

import (
	"encoding/json"
	"fmt"

	"github.com/0xharryriddle/DQNSB_Scheme/src/node"
)

type ConsensusMessage struct {
	Type      MessageType `json:"type"`
	Sender    node.NodeID `json:"sender"`
	Receiver  node.NodeID `json:"receiver"`
	Timestamp int64       `json:"timestamp"`
	Payload   []byte      `json:"payload"`
	Signature []byte      `json:"signature"`
}

func (msg *ConsensusMessage) String() string {
	return fmt.Sprintf("\n======Consensus Messagetype======"+
		"\ntype:%40s"+
		"\nsig:%40s"+
		"\npayload:%d"+
		"\n<------------------>",
		msg.Type.String(),
		msg.Signature,
		len(msg.Payload))
}

func (msg *ConsensusMessage) Verify() bool {
	//hash := HASH(msg.Payload)
	//return msg.Sender == Revert(hash, msg.Sig)
	return true
}

func CreateConsensusMessage(msgType MessageType, msg interface{}) *ConsensusMessage {
	data, err := json.Marshal(msg)
	if err != nil {
		fmt.Printf("Error marshalling message: %v\n", err)
		return nil
	}

	signature := fmt.Sprintf("consensus message[%s]", msgType)
	consMsg := &ConsensusMessage{
		Type:      msgType,
		Signature: []byte(signature),
		Payload:   data,
	}
	return consMsg
}

type RequestRecord struct {
	*PrePrepare
	*Request
}

type PrePrepare struct {
	ViewID     int64  `json:"viewID"`
	SequenceID int64  `json:"sequenceID"`
	Digest     string `json:"digest"`
}

type PrepareMessage map[int64]*Prepare

type Prepare struct {
	ViewID     int64       `json:"viewID"`
	SequenceID int64       `json:"sequenceID"`
	Digest     string      `json:"digest"`
	NodeID     node.NodeID `json:"nodeID"`
}

type Commit struct {
	ViewID     int64       `json:"viewID"`
	SequenceID int64       `json:"sequenceID"`
	Digest     string      `json:"digest"`
	NodeID     node.NodeID `json:"nodeID"`
}

type Checkpoint struct {
	SequenceID int64       `json:"sequenceID"`
	Digest     string      `json:"digest"`
	ViewID     int64       `json:"viewID"`
	NodeID     node.NodeID `json:"nodeID"`
}

type PrepareTuple struct {
	PrepareMessage    PrepareMessage `json:"prepare"`
	PrePrepareMessage *PrePrepare    `json:"prePrepare"`
}

type ViewChange struct {
	NewViewID         int64                   `json:"newViewID"`
	LastCPSequence    int64                   `json:"lastCPSequence"`
	NodeID            node.NodeID             `json:"nodeID"`
	CheckpointMessage map[int64]*Checkpoint   `json:"checkpointMessage"`
	PrepareMessage    map[int64]*PrepareTuple `json:"prepareMessage"`
}

func (vc *ViewChange) Digest() string {
	return fmt.Sprintf("this is digest for[%d-%d]", vc.NewViewID, vc.LastCPSequence)
}

type OMessage map[int64]*PrePrepare

func (m *OMessage) Equal(msg *OMessage) bool {
	//return HASH(m) == HASH(msg)
	return true
}

type ViewChangeMessage map[int64]*ViewChange

type NewView struct {
	NewViewID         int64             `json:"newViewID"`
	ViewChangeMessage ViewChangeMessage `json:"viewChangeMessage"`
	OMessage          OMessage          `json:"oMessage"`
	NMessage          OMessage          `json:"nMessage"`
}
