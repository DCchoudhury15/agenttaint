package taintpolicy

import (
	"context"
	_ "embed"
	"encoding/json"
	"fmt"
	"os"
	"regexp"
	"strings"

	"github.com/open-policy-agent/opa/rego"

	"go.opentelemetry.io/collector/component"
	"go.opentelemetry.io/collector/consumer"
	"go.opentelemetry.io/collector/pdata/pcommon"
	"go.opentelemetry.io/collector/pdata/ptrace"
	"go.opentelemetry.io/collector/processor"
)

var _ processor.Traces = (*taintPolicyProcessor)(nil)

//go:embed pii_egress.rego
var embeddedPolicy string

// policyAttrs read off each span to feed the Rego policy.
const (
	attSensitive    = "agentward.sensitive"
	attClasses      = "agentward.taint.classes"
	attDestination  = "agentward.destination"
	attJurisdiction = "agentward.jurisdiction"
	attTool         = "gen_ai.tool.name"
)

// policyAttrs written by the collector (authoritative: Rego is the source of truth).
const (
	attPolicyRedact           = "agentward.policy.redacted"
	attPolicyViolation        = "agentward.policy.violation"
	attPolicyTransfer         = "agentward.policy.transfer_violation"
	attPolicyViolations       = "agentward.policy.violations"
	attPolicyReasons          = "agentward.policy.reasons"
	attPolicyDecision         = "agentward.policy.decision_engine"
	decisionEngine            = "rego"
)

// taintPolicyProcessor is a traces processor that:
//  1. reads agentward.* attrs off each span,
//  2. evaluates the embedded Rego policy (compile-once / eval-many),
//  3. writes collector-authoritative agentward.policy.* attrs, and
//  4. redacts raw PII from span string attributes so SigNoz never stores it.
type taintPolicyProcessor struct {
	cfg      *Config
	next     consumer.Traces
	prepared rego.PreparedEvalQuery
}

var _ processor.Traces = (*taintPolicyProcessor)(nil)

func newProcessor(cfg *Config, next consumer.Traces) (*taintPolicyProcessor, error) {
	policySrc := embeddedPolicy
	if cfg.PolicyPath != "" {
		b, err := os.ReadFile(cfg.PolicyPath)
		if err != nil {
			return nil, fmt.Errorf("taint_policy: read policy_path %q: %w", cfg.PolicyPath, err)
		}
		policySrc = string(b)
	}
	// Compile once at startup; eval many per span.
	prepared, err := rego.New(
		rego.Query("data.agentward.decision"),
		rego.Module("pii_egress.rego", policySrc),
	).PrepareForEval(context.Background())
	if err != nil {
		return nil, fmt.Errorf("taint_policy: compile rego: %w", err)
	}
	return &taintPolicyProcessor{cfg: cfg, next: next, prepared: prepared}, nil
}

// Capabilities: mutates span data.
func (p *taintPolicyProcessor) Capabilities() consumer.Capabilities {
	return consumer.Capabilities{MutatesData: true}
}

// Start / Shutdown satisfy component.Component (no setup/teardown needed).
func (p *taintPolicyProcessor) Start(context.Context, component.Host) error { return nil }
func (p *taintPolicyProcessor) Shutdown(context.Context) error              { return nil }

// ConsumeTraces evaluates the policy on every span, redacts in place, then
// forwards to the next consumer in the pipeline.
func (p *taintPolicyProcessor) ConsumeTraces(ctx context.Context, td ptrace.Traces) error {
	for i := 0; i < td.ResourceSpans().Len(); i++ {
		rs := td.ResourceSpans().At(i)
		for j := 0; j < rs.ScopeSpans().Len(); j++ {
			ss := rs.ScopeSpans().At(j)
			for k := 0; k < ss.Spans().Len(); k++ {
				p.processSpan(ctx, ss.Spans().At(k))
			}
		}
	}
	return p.next.ConsumeTraces(ctx, td)
}

func (p *taintPolicyProcessor) processSpan(ctx context.Context, span ptrace.Span) {
	attrs := span.Attributes()

	input := map[string]interface{}{
		"sensitive":    getBool(attrs, attSensitive),
		"classes":      getStr(attrs, attClasses),
		"destination":  getStr(attrs, attDestination),
		"jurisdiction": getStr(attrs, attJurisdiction),
		"tool":         getStr(attrs, attTool),
	}

	results, err := p.prepared.Eval(ctx, rego.EvalInput(input))
	if err != nil {
		// Policy eval failure must never drop telemetry: record and skip.
		span.Attributes().PutStr("agentward.policy.error", err.Error())
		return
	}
	if len(results) == 0 || len(results[0].Expressions) == 0 {
		return
	}
	decision, ok := results[0].Expressions[0].Value.(map[string]interface{})
	if !ok {
		return
	}

	redact, _ := decision["redact"].(bool)
	violations, _ := decision["violations"].([]interface{})

	var anyViolation, anyTransfer bool
	var reasons []string
	for _, v := range violations {
		m, ok := v.(map[string]interface{})
		if !ok {
			continue
		}
		anyViolation = true
		rule, _ := m["rule"].(string)
		reasons = append(reasons, rule)
		if rule == "transfer" {
			anyTransfer = true
		}
	}
	violJSON, _ := json.Marshal(violations)

	attrs.PutBool(attPolicyRedact, redact)
	attrs.PutBool(attPolicyViolation, anyViolation)
	attrs.PutBool(attPolicyTransfer, anyTransfer)
	attrs.PutStr(attPolicyViolations, string(violJSON))
	attrs.PutStr(attPolicyReasons, strings.Join(reasons, ","))
	attrs.PutStr(attPolicyDecision, decisionEngine)

	// Redact raw PII from span string attributes so the storage backend
	// (SigNoz/ClickHouse) never persists the secret.
	if redact {
		redactSpan(attrs)
	}
}

// --- attribute helpers ---

func getStr(m pcommon.Map, key string) string {
	v, ok := m.Get(key)
	if !ok || v.Type() != pcommon.ValueTypeStr {
		return ""
	}
	return v.Str()
}

func getBool(m pcommon.Map, key string) bool {
	v, ok := m.Get(key)
	if !ok || v.Type() != pcommon.ValueTypeBool {
		return false
	}
	return v.Bool()
}

// --- redaction (Go-side backstop; the SDK also masks, this is the gate) ---

type pattern struct {
	re   *regexp.Regexp
	mask string
}

var patterns = []pattern{
	{regexp.MustCompile(`AKIA[0-9A-Z]{16}`), "[SECRET]"},
	{regexp.MustCompile(`gh[pousr]_[A-Za-z0-9]{36}`), "[SECRET]"},
	{regexp.MustCompile(`\b\d{3}-\d{2}-\d{4}\b`), "[PII]"},
	{regexp.MustCompile(`[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}`), "[PII]"},
	{regexp.MustCompile(`\b\d{3}[-.\s]\d{3}[-.\s]\d{4}\b`), "[PII]"},
}

func maskPII(s string) (string, bool) {
	changed := false
	for _, p := range patterns {
		if p.re.MatchString(s) {
			s = p.re.ReplaceAllString(s, p.mask)
			changed = true
		}
	}
	return s, changed
}

func redactSpan(attrs pcommon.Map) {
	type kv struct{ k, v string }
	var pending []kv
	attrs.Range(func(k string, v pcommon.Value) bool {
		// The SDK egress gate already redacts gen_ai.tool.call.arguments
		// (Phase 4: reversible FPE for internal, mask for egress). Re-redacting
		// here would mask the format-preserving tokens (they match PII regexes)
		// and destroy reversibility in observability. The collector stays the
		// backstop for the result attr and any other residual string attrs.
		if k == "gen_ai.tool.call.arguments" {
			return true
		}
		if v.Type() == pcommon.ValueTypeStr {
			if masked, changed := maskPII(v.Str()); changed {
				pending = append(pending, kv{k, masked})
			}
		}
		return true
	})
	for _, e := range pending {
		attrs.PutStr(e.k, e.v)
	}
}