package pbft

type Mode int

const (
	Normal     Mode = iota
	ViewChange      //
)

type Consensus interface {
	StartConsensus()
	PrePrepare()
	Prepare()
	Commit()
}

type State int

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

	NodeID NodeID
}

type SealedProposal struct {
	// Proposal *Proposal
	CommittedSeals []CommittedSeal
	Proposer       NodeID
	Number         int
}

type RoundInfo struct {
	IsProposer   bool
	Proposer     NodeID
	Locked       bool
	CurrentRound int
}

type Pbft struct {
	logger Logger
}
