package rule

import (
	"cmp"
	"context"
	"runtime"
	"slices"
	"sync"
	"time"

	"github.com/sagernet/sing-box/adapter"
)

type RuleSetUpdater struct {
	ctx      context.Context
	cancel   context.CancelFunc
	ruleSets []*RemoteRuleSet
	// requests are updates asked for now, each with where to answer
	requests chan chan RuleSetUpdateSummary
}

// RuleSetUpdateSummary is what an update of the remote rule-sets came to.
type RuleSetUpdateSummary struct {
	// Total is the number of remote rule-sets.
	Total int
	// Loaded is how many of them got a new list.
	Loaded int
	// Failed is how many could not be downloaded or read.
	Failed int
}

func NewRuleSetUpdater(ctx context.Context, ruleSets []adapter.RuleSet) *RuleSetUpdater {
	var remoteRuleSets []*RemoteRuleSet
	for _, ruleSet := range ruleSets {
		remoteRuleSet, isRemote := ruleSet.(*RemoteRuleSet)
		if isRemote {
			remoteRuleSets = append(remoteRuleSets, remoteRuleSet)
		}
	}
	if len(remoteRuleSets) == 0 {
		return nil
	}
	ctx, cancel := context.WithCancel(ctx)
	return &RuleSetUpdater{
		ctx:      ctx,
		cancel:   cancel,
		ruleSets: remoteRuleSets,
		requests: make(chan chan RuleSetUpdateSummary),
	}
}

func (u *RuleSetUpdater) Start() {
	go u.loopUpdate()
}

func (u *RuleSetUpdater) Close() error {
	u.cancel()
	return nil
}

// ruleSetUpdateConcurrency is how many rule-sets an update downloads at once, as many as
// the start does (route.Router): rule-sets that start empty, or that are due together,
// are not fetched one after another.
const ruleSetUpdateConcurrency = 5

// UpdateNow updates every remote rule-set at once, whatever its update_interval, and
// returns what that came to. The update runs where the scheduled ones run, up to
// ruleSetUpdateConcurrency rule-sets at a time; the next scheduled update of each is
// counted from now.
func (u *RuleSetUpdater) UpdateNow(ctx context.Context) (RuleSetUpdateSummary, error) {
	reply := make(chan RuleSetUpdateSummary, 1)
	select {
	case u.requests <- reply:
	case <-u.ctx.Done():
		return RuleSetUpdateSummary{}, u.ctx.Err()
	case <-ctx.Done():
		return RuleSetUpdateSummary{}, ctx.Err()
	}
	select {
	case summary := <-reply:
		return summary, nil
	case <-u.ctx.Done():
		return RuleSetUpdateSummary{}, u.ctx.Err()
	case <-ctx.Done():
		return RuleSetUpdateSummary{}, ctx.Err()
	}
}

func (u *RuleSetUpdater) loopUpdate() {
	nextUpdates := make([]time.Time, len(u.ruleSets))
	retryDelays := make([]time.Duration, len(u.ruleSets))
	for i, ruleSet := range u.ruleSets {
		nextUpdates[i] = ruleSet.lastUpdated.Add(ruleSet.updateInterval)
	}
	timer := time.NewTimer(0)
	defer timer.Stop()
	for {
		// an update asked for now takes every rule-set, due or not
		var reply chan RuleSetUpdateSummary
		select {
		case <-u.ctx.Done():
			return
		case <-timer.C:
		case reply = <-u.requests:
		}
		now := time.Now()
		var loaded bool
		summary := RuleSetUpdateSummary{Total: len(u.ruleSets)}
		var due []int
		for i := range u.ruleSets {
			if reply == nil && now.Before(nextUpdates[i]) {
				continue
			}
			due = append(due, i)
		}
		results := u.updateAll(due)
		if u.ctx.Err() != nil {
			// closed during the update: nothing recovered is told of a closed box
			return
		}
		for _, i := range due {
			ruleSet := u.ruleSets[i]
			if results[i].loaded {
				loaded = true
				summary.Loaded++
			} else if results[i].failed {
				summary.Failed++
			}
			nextUpdates[i] = now.Add(ruleSet.updateInterval)
			if ruleSet.startedEmpty {
				if ruleSet.lastUpdated.IsZero() {
					// Never downloaded (initial fetch failed): retry with backoff
					// instead of waiting a whole update_interval.
					retryDelays[i] = min(max(retryDelays[i]*2, 5*time.Second), 30*time.Second)
					nextUpdates[i] = now.Add(retryDelays[i])
				} else {
					ruleSet.startedEmpty = false
					notifyRuleSetRecovered(ruleSet.logger, ruleSet.tag)
				}
			}
		}
		if reply != nil {
			reply <- summary
		}
		// the old list is garbage once a new one is loaded; a failed or not-modified
		// update leaves nothing to collect
		if loaded {
			runtime.GC()
		}
		timer.Reset(waitUntilNext(nextUpdates))
	}
}

// updateResult is what one update of a rule-set came to.
type updateResult struct {
	loaded bool
	failed bool
}

// heavyRuleSetSize is the size of a list from which its update waits for the update of
// any other such list (podkop-engine): the download holds the list, the parse builds the
// next one beside the one in use, and the save writes it; big lists updated together took
// all of that at once. Small lists, and those that hold nothing yet, go together as before.
const heavyRuleSetSize = 1 << 20

// updateAll updates the rule-sets of the indexes, ruleSetUpdateConcurrency at a time and
// the big ones one at a time, and returns what each came to, by index. A rule-set is
// touched by one goroutine only.
func (u *RuleSetUpdater) updateAll(indexes []int) []updateResult {
	results := make([]updateResult, len(u.ruleSets))
	slots := make(chan struct{}, ruleSetUpdateConcurrency)
	heavy := make(chan struct{}, 1)
	isHeavy := func(i int) bool {
		return u.ruleSets[i].contentSize.Load() >= heavyRuleSetSize
	}
	// the small ones first: big ones waiting for each other hold slots meanwhile
	indexes = slices.Clone(indexes)
	slices.SortStableFunc(indexes, func(left int, right int) int {
		return cmp.Compare(boolOrder(isHeavy(left)), boolOrder(isHeavy(right)))
	})
	var group sync.WaitGroup
	for _, i := range indexes {
		group.Add(1)
		slots <- struct{}{}
		go func(i int) {
			defer group.Done()
			defer func() { <-slots }()
			if isHeavy(i) {
				heavy <- struct{}{}
				defer func() { <-heavy }()
			}
			ruleSet := u.ruleSets[i]
			failures := ruleSet.failures
			results[i].loaded = ruleSet.updateOnce()
			results[i].failed = !results[i].loaded && ruleSet.failures > failures
		}(i)
	}
	group.Wait()
	return results
}

func boolOrder(value bool) int {
	if value {
		return 1
	}
	return 0
}

func waitUntilNext(nextUpdates []time.Time) time.Duration {
	next := nextUpdates[0]
	for _, nextUpdate := range nextUpdates[1:] {
		if nextUpdate.Before(next) {
			next = nextUpdate
		}
	}
	wait := time.Until(next)
	if wait < 0 {
		return 0
	}
	return wait
}
