package message

import "fmt"

type MessageType int16

const (
	MessageTypePrePrepare MessageType = iota
	MessageTypeRequest
	MessageTypeResponse
	MessageTypeCommit
	MessageTypeCheckpoint
	MessageTypeViewChange
	MessageTypeNewView
)

func (mt MessageType) String() string {
	switch mt {
	case MessageTypePrePrepare:
		return "PrePrepare"
	case MessageTypeRequest:
		return "Request"
	case MessageTypeResponse:
		return "Response"
	case MessageTypeCommit:
		return "Commit"
	case MessageTypeCheckpoint:
		return "Checkpoint"
	case MessageTypeViewChange:
		return "ViewChange"
	case MessageTypeNewView:
		return "NewView"
	default:
		return "Unknown"
	}
}

type Request struct {
	SequenceID int64  `json:"sequenceID"`
	TimeStamp  int64  `json:"timestamp"`
	ClientID   string `json:"clientID"`
	Operation  string `json:"operation"`
}

func (r *Request) String() string {
	return fmt.Sprintf("Request[SequenceID: %d, TimeStamp: %d, ClientID: %s, Operation: %s]", r.SequenceID, r.TimeStamp, r.ClientID, r.Operation)
}
