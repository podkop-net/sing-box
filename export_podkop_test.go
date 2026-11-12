package box

import (
	"time"

	"github.com/sagernet/sing-box/common/trafficcontrol"
	"github.com/sagernet/sing/service"
)

// What the tests of UpdateOutbounds (box_podkop_test.go) look at.

func (s *Box) DrainOnce(now time.Time) bool {
	return s.drainOnce(now)
}

func (s *Box) KeptOutbounds() int {
	s.hot.access.Lock()
	defer s.hot.access.Unlock()
	return len(s.hot.kept)
}

func (s *Box) TrafficManager() *trafficcontrol.Manager {
	return service.PtrFromContext[trafficcontrol.Manager](s.scope.Context())
}

// DrainEvery sets how often the kept outbounds are looked at, until restore is called.
func DrainEvery(every time.Duration) (restore func()) {
	before := drainEvery
	drainEvery = every
	return func() { drainEvery = before }
}

var DrainMin, DrainMax = drainMin, drainMax
