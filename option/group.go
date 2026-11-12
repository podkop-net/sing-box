package option

import "github.com/sagernet/sing/common/json/badoption"

type SelectorOutboundOptions struct {
	Outbounds                 []string `json:"outbounds" reference:"outbound"`
	Default                   string   `json:"default,omitempty" reference:"outbound"`
	InterruptExistConnections bool     `json:"interrupt_exist_connections,omitempty"`
}

type URLTestOutboundOptions struct {
	Outbounds                 []string           `json:"outbounds" reference:"outbound"`
	Fallbacks                 []string           `json:"fallbacks,omitempty" reference:"outbound"`
	URL                       string             `json:"url,omitempty"`
	DownloadURL               *string            `json:"download_url,omitempty"`
	Interval                  badoption.Duration `json:"interval,omitempty"`
	Tolerance                 uint16             `json:"tolerance,omitempty"`
	IdleTimeout               badoption.Duration `json:"idle_timeout,omitempty"`
	InterruptExistConnections bool               `json:"interrupt_exist_connections,omitempty"`
	// URLs are the URLs of the tests, one a round in turn; url is left out when they are set
	// (podkop-engine)
	URLs badoption.Listable[string] `json:"urls,omitempty"`
	// Mode is how the group chooses (podkop-engine): fastest (the default), loss (the
	// fastest, the delays weighed by the loss loss probes count through loss_url once a
	// loss_interval) or balance (the connections spread by their source over at most
	// balance_size best members, none losing more than loss_threshold percent; a device
	// moves after balance_idle without a connection)
	Mode          string             `json:"mode,omitempty"`
	LossURL       string             `json:"loss_url,omitempty"`
	LossInterval  badoption.Duration `json:"loss_interval,omitempty"`
	LossThreshold float64            `json:"loss_threshold,omitempty"`
	BalanceSize   int                `json:"balance_size,omitempty"`
	BalanceIdle   badoption.Duration `json:"balance_idle,omitempty"`
}
