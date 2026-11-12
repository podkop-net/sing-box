package group

import "github.com/sagernet/sing-box/adapter"

// ReleaseMembers lets go of the members but the chosen one, a while after another selector
// took the tag: nothing asks this one for a member by its tag any more.
func (s *Selector) ReleaseMembers() {
	s.outbounds = make(map[string]adapter.Outbound)
}
