package pbft

import (
	"time"

	"github.com/0xharryriddle/DQNSB_Scheme/stats"
)

type NodeID string

const (
	defaultTimeout     = 2 * time.Second
	maxTimeout         = 300 * time.Second
	maxTimeoutExponent = 8
)

type RoundTimeout func(round int) <-chan time.Time

type StatsCallback func(stats.Stats)
