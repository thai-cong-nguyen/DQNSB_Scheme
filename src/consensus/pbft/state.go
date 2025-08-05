package pbft

import "github.com/0xharryriddle/DQNSB_Scheme/src/node"

type Mode int64

const (
	Normal Mode = iota
	ViewChange
)

type Consensus interface {
	StartConsensus()
	PrePrepare()
	Prepare()
	Commit()
}

type State int64

const (
	AcceptState State = iota
	RoundChangeState
	ValidateState
	CommitState
	SyncState
	DoneState
)

func (s State) String() string {
	switch s {
	case AcceptState:
		return "AcceptState"
	case RoundChangeState:
		return "RoundChangeState"
	case ValidateState:
		return "ValidateState"
	case CommitState:
		return "CommitState"
	case SyncState:
		return "SyncState"
	case DoneState:
		return "DoneState"
	default:
		return "Unknown State"
	}
}

type CommittedSeal struct {
	Signature []byte

	NodeID node.NodeID
}

type SealedProposal struct {
	// Proposal *Proposal
	CommittedSeals []CommittedSeal
	Proposer       node.NodeID
	Number         int64
}

type RoundInfo struct {
	IsProposer   bool
	Proposer     node.NodeID
	Locked       bool
	CurrentRound int64
}

type Pbft struct {
	logger Logger
}
