package stats

import (
	"sync"
	"time"
)

type Stats struct {
	lock *sync.Mutex

	round int

	sequence int

	msgCount       map[string]int
	msgVotingPower map[string]int
	stateDuration  map[string]time.Duration
}

func NewStats() *Stats {
	return &Stats{
		lock:           &sync.Mutex{},
		msgCount:       make(map[string]int),
		msgVotingPower: make(map[string]int),
		stateDuration:  make(map[string]time.Duration),
	}
}

func (s *Stats) SetView(sequence int, round int) {
	s.lock.Lock()
	defer s.lock.Unlock()
	s.sequence = sequence
	s.round = round
}

func (s *Stats) IncrMsgCount(msgType string, votingPower int) {
	s.lock.Lock()
	defer s.lock.Unlock()
	s.msgCount[msgType]++
	s.msgVotingPower[msgType] += votingPower
}

func (s *Stats) StateDuration(state string, t time.Time) {
	s.lock.Lock()
	defer s.lock.Unlock()
	s.stateDuration[state] += time.Since(t)
}

func (s *Stats) Snapshot() Stats {
	stats := NewStats()
	s.lock.Lock()
	defer s.lock.Unlock()

	stats.round = s.round
	stats.sequence = s.sequence

	for msgType, count := range s.msgCount {
		stats.msgCount[msgType] = count
	}

	for msgType, votingPower := range s.msgVotingPower {
		stats.msgVotingPower[msgType] = votingPower
	}

	for state, duration := range s.stateDuration {
		stats.stateDuration[state] = duration
	}

	return *stats
}

func (s *Stats) Reset() {
	s.lock.Lock()
	defer s.lock.Unlock()

	s.msgCount = make(map[string]int)
	s.msgVotingPower = make(map[string]int)
	s.stateDuration = make(map[string]time.Duration)
}
