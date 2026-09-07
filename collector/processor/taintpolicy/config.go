package taintpolicy

import "go.opentelemetry.io/collector/component"

// Config for the taint_policy processor.
//
//   policy_path: optional override to load pii_egress.rego from disk at
//   startup (enables "edit rules without rebuild"). When empty, the
//   embedded policy is used.
type Config struct {
	PolicyPath string `mapstructure:"policy_path,omitempty"`
}

func createDefaultConfig() component.Config {
	return &Config{}
}

var _ component.Config = (*Config)(nil)