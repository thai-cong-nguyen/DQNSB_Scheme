package message

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
