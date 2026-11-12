package rule

import (
	"os"
	"os/exec"
	"strings"
	"sync"
	"time"

	"github.com/sagernet/sing/common/logger"
)

// RuleSetRecoveredHookEnv names a command run once remote rule-sets that could
// not be downloaded at start have been downloaded after all: the network path
// to the lists works now, so whatever else depends on it (e.g. podkop's own
// list download) can be retried. Unset: nothing happens.
const RuleSetRecoveredHookEnv = "SING_BOX_RULESET_RECOVERED_HOOK"

// Rule-sets recovering close together are reported by a single run.
var ruleSetRecoveredHookDelay = 5 * time.Second

var ruleSetRecovered struct {
	access sync.Mutex
	timer  *time.Timer
	tags   []string
}

func notifyRuleSetRecovered(logger logger.ContextLogger, tag string) {
	command := os.Getenv(RuleSetRecoveredHookEnv)
	if command == "" {
		return
	}
	ruleSetRecovered.access.Lock()
	defer ruleSetRecovered.access.Unlock()
	ruleSetRecovered.tags = append(ruleSetRecovered.tags, tag)
	if ruleSetRecovered.timer != nil {
		return
	}
	ruleSetRecovered.timer = time.AfterFunc(ruleSetRecoveredHookDelay, func() {
		ruleSetRecovered.access.Lock()
		tags := strings.Join(ruleSetRecovered.tags, ",")
		ruleSetRecovered.tags = nil
		ruleSetRecovered.timer = nil
		ruleSetRecovered.access.Unlock()
		cmd := exec.Command("/bin/sh", "-c", command)
		cmd.Env = append(os.Environ(), "SING_BOX_RULESET_TAGS="+tags)
		// The output of the command is not taken: the command may outlive this process
		// (a list update that restarts the service), and a pipe whose reader is gone
		// would end it at its next write. How it ended is in its exit status.
		err := cmd.Start()
		if err != nil {
			logger.Error("run rule-set recovered hook: ", err)
			return
		}
		logger.Info("rule-set recovered hook started for ", tags)
		go func() {
			err := cmd.Wait()
			if err != nil {
				logger.Error("rule-set recovered hook for ", tags, ": ", err)
			} else {
				logger.Debug("rule-set recovered hook for ", tags, " finished")
			}
		}()
	})
}
