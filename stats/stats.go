package stats

import (
	"fmt"
	"io"
	"sync"
	"sync/atomic"
	"time"

	"mtproxy/config"
)

// ── 统计数据 ──────────────────────────────────────────────────────────────────

type Stats struct {
	Mu sync.RWMutex

	ConnectsAll       int64
	ConnectsBad       int64
	HandshakeTimeouts int64

	ConnectsByDuration map[float64]int64

	SecretStats map[string]*SecretStat // key: hex secret
}

type SecretStat struct {
	Connects      int64
	CurrConnects  int64
	OctetsFromClt int64
	OctetsToClt   int64
	MsgsFromClt   int64
	MsgsToClt     int64
}

var GlobalStats = &Stats{
	ConnectsByDuration: make(map[float64]int64),
	SecretStats:        make(map[string]*SecretStat),
}

var ProxyStartTime = time.Now()

var DurationBuckets = []float64{0.1, 0.5, 1, 2, 5, 15, 60, 300, 600, 1800, 1e9}

func (s *Stats) IncConnectsAll()         { atomic.AddInt64(&s.ConnectsAll, 1) }
func (s *Stats) IncConnectsBad()         { atomic.AddInt64(&s.ConnectsBad, 1) }
func (s *Stats) IncHandshakeTimeouts()   { atomic.AddInt64(&s.HandshakeTimeouts, 1) }

func (s *Stats) UpdateDuration(d float64) {
	s.Mu.Lock()
	defer s.Mu.Unlock()
	for _, bucket := range DurationBuckets {
		if d <= bucket {
			s.ConnectsByDuration[bucket]++
			return
		}
	}
}

func (s *Stats) GetOrCreateSecretStat(secretHex string) *SecretStat {
	s.Mu.Lock()
	defer s.Mu.Unlock()
	if st, ok := s.SecretStats[secretHex]; ok {
		return st
	}
	st := &SecretStat{}
	s.SecretStats[secretHex] = st
	return st
}

func (ss *SecretStat) IncConnects()             { atomic.AddInt64(&ss.Connects, 1) }
func (ss *SecretStat) AddCurrConnects(n int64)  { atomic.AddInt64(&ss.CurrConnects, n) }
func (ss *SecretStat) AddOctetsFromClt(n int64) { atomic.AddInt64(&ss.OctetsFromClt, n) }
func (ss *SecretStat) AddOctetsToClt(n int64)   { atomic.AddInt64(&ss.OctetsToClt, n) }
func (ss *SecretStat) AddMsgsFromClt(n int64)   { atomic.AddInt64(&ss.MsgsFromClt, n) }
func (ss *SecretStat) AddMsgsToClt(n int64)     { atomic.AddInt64(&ss.MsgsToClt, n) }

func StatsPrinter(cfg *config.Config, logf func(string, ...interface{})) {
	for {
		time.Sleep(time.Duration(cfg.StatsPrintPeriod) * time.Second)
		logf("Stats for %s\n", time.Now().Format("02.01.2006 15:04:05"))
		GlobalStats.Mu.RLock()
		for secretHex, st := range GlobalStats.SecretStats {
			total := atomic.LoadInt64(&st.OctetsFromClt) + atomic.LoadInt64(&st.OctetsToClt)
			fmt.Fprintf(io.Discard, "") // avoid unused import
			logf("%s: %d connects (%d current), %.2f MB, %d msgs\n",
				secretHex[:8]+"...",
				atomic.LoadInt64(&st.Connects),
				atomic.LoadInt64(&st.CurrConnects),
				float64(total)/1e6,
				atomic.LoadInt64(&st.MsgsFromClt)+atomic.LoadInt64(&st.MsgsToClt),
			)
		}
		GlobalStats.Mu.RUnlock()
		logf("\n")
	}
}
