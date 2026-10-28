package adapter

import (
	"maps"
	"slices"

	E "github.com/sagernet/sing/common/exceptions"
)

// CloseComponent closes the scopes a component was started in, found among the children of
// this scope and theirs, and lets go of them: the scopes hold the component no more. The
// cleanups that close them with their parents stay and do nothing then. It tells whether the
// component was found (podkop-engine: an outbound that was replaced while the box runs is
// closed alone).
//
// A component may have more than one: the outbound manager starts an outbound in its scope,
// but the start stage of one that is a Lifecycle in the scope of the endpoint manager (it is
// an adapter.Endpoint by its methods).
func (s *Scope) CloseComponent(component Lifecycle) (bool, error) {
	taken := s.takeChildren(component, nil)
	var errors []error
	for _, child := range taken {
		errors = append(errors, child.Close())
	}
	return len(taken) > 0, E.Errors(errors...)
}

func (s *Scope) takeChildren(component Lifecycle, taken []*Scope) []*Scope {
	s.access.Lock()
	if child, loaded := s.children[component]; loaded {
		delete(s.children, component)
		taken = append(taken, child)
	}
	children := slices.Collect(maps.Values(s.children))
	s.access.Unlock()
	for _, child := range children {
		taken = child.takeChildren(component, taken)
	}
	return taken
}
