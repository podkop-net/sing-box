package rule

import "time"

// SwapTimeoutsForTest exposes the fetch bounds to the tests outside the package.
func SwapTimeoutsForTest(stall, startDeadline time.Duration) func() {
	return swapTimeouts(stall, startDeadline)
}
