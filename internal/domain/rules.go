package domain

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"math"
	"sort"
	"time"
)

func ActivatePlan(plan *RolloutPlan, now time.Time) error {
	if plan.State != PlanDraft {
		return InvalidState("plan can be activated only from draft", map[string]any{
			"plan_id": plan.ID,
			"state":   plan.State,
		})
	}
	if plan.LatestRevisionID == "" {
		return InvalidState("plan needs a zone revision before activation", map[string]any{
			"plan_id": plan.ID,
		})
	}
	plan.State = PlanActive
	plan.ActivatedAt = timePointer(now.UTC())
	plan.Version++
	return nil
}

func CompletePlan(plan *RolloutPlan, now time.Time) error {
	if plan.State != PlanActive {
		return InvalidState("plan can be completed only from active", map[string]any{
			"plan_id": plan.ID,
			"state":   plan.State,
		})
	}
	plan.State = PlanCompleted
	plan.CompletedAt = timePointer(now.UTC())
	plan.Version++
	return nil
}

func UpsertNodeAdmission(state *State, admission NodeAdmission) NodeAdmission {
	if state.NodeAdmissions == nil {
		state.NodeAdmissions = make(map[string]NodeAdmission)
	}
	current, exists := state.NodeAdmissions[admission.NodeID]
	if !exists {
		current = NodeAdmission{
			NodeID:     admission.NodeID,
			RecordedAt: admission.RecordedAt.UTC(),
		}
	}
	if admission.NodeName != "" {
		current.NodeName = admission.NodeName
	}
	if admission.Region != "" {
		current.Region = admission.Region
	}
	if admission.Quarantined {
		current.Quarantined = true
	}
	if !admission.RecordedAt.IsZero() {
		current.RecordedAt = admission.RecordedAt.UTC()
	}
	state.NodeAdmissions[current.NodeID] = current
	return current
}

// NodeAvailable reports whether a node can receive a new lease. Quarantine is
// a durable admission decision that blocks allocation until it is explicitly
// lifted, regardless of the node's displayed state.
func NodeAvailable(state *State, node ResolverNode) bool {
	if state == nil || node.ID == "" {
		return false
	}
	if node.State == NodeLeased || node.State == NodeQuarantined {
		return false
	}
	if admission, ok := state.NodeAdmissions[node.ID]; ok {
		if admission.Quarantined {
			return false
		}
	}
	return node.State == NodeReady
}

// ApplyNodeAdmission ends the current occupancy on a node. A released,
// reported, or expired lease can only finish the current hold: a quarantined
// node returns to the quarantined state instead of becoming ready.
func ApplyNodeAdmission(state *State, node *ResolverNode, occupied bool, now time.Time) {
	if node == nil {
		return
	}
	quarantined := false
	if state != nil {
		if admission, ok := state.NodeAdmissions[node.ID]; ok {
			if admission.NodeName != "" {
				node.NodeName = admission.NodeName
			}
			if admission.Region != "" {
				node.Region = admission.Region
			}
			quarantined = admission.Quarantined
		}
	}
	switch {
	case occupied:
		node.State = NodeLeased
	case quarantined:
		node.State = NodeQuarantined
	default:
		node.State = NodeReady
	}
	node.Version++
	node.UpdatedAt = now.UTC()
}

func LeaseFingerprint(planID string, input LeaseInput) string {
	payload := fmt.Sprintf(
		"%s|%s|%s|%d|%d",
		planID,
		input.RequestKey,
		input.Region,
		input.LeaseSeconds,
		input.MaxNodes,
	)
	sum := sha256.Sum256([]byte(payload))
	return hex.EncodeToString(sum[:])
}

func ProbeFingerprint(leaseID string, input ProbeInput) string {
	payload := fmt.Sprintf(
		"%s|%s|%t|%d|%d|%s",
		leaseID,
		input.RequestKey,
		input.Success,
		input.ObservedSerial,
		input.LatencyMS,
		input.ObservedAt.UTC().Format(time.RFC3339Nano),
	)
	sum := sha256.Sum256([]byte(payload))
	return hex.EncodeToString(sum[:])
}

func BuildAssessment(
	id string,
	plan RolloutPlan,
	revision ZoneRevision,
	probes []Probe,
	now time.Time,
) RolloutAssessment {
	reasons := make(map[string]struct{})
	if len(probes) == 0 {
		reasons["no_probes"] = struct{}{}
	}
	probeCount := len(probes)
	successCount := 0
	maximumLatency := 0
	nodes := make(map[string]struct{})
	for _, probe := range probes {
		nodes[probe.NodeID] = struct{}{}
		if probe.LatencyMS > maximumLatency {
			maximumLatency = probe.LatencyMS
		}
		if probe.Success {
			successCount++
			if probe.ObservedSerial != revision.Serial {
				reasons["serial_mismatch"] = struct{}{}
			}
		}
	}
	if len(nodes) < plan.ExpectedNodes {
		reasons["node_not_observed"] = struct{}{}
	}
	successRatio := 0.0
	if probeCount > 0 {
		successRatio = round(float64(successCount)/float64(probeCount), 6)
	}
	if successRatio < plan.MinimumSuccessRatio {
		reasons["success_ratio_below_minimum"] = struct{}{}
	}
	if maximumLatency > plan.MaximumLatencyMS {
		reasons["latency_limit_exceeded"] = struct{}{}
	}
	reasonList := make([]string, 0, len(reasons))
	for reason := range reasons {
		reasonList = append(reasonList, reason)
	}
	sort.Strings(reasonList)
	verdict := VerdictConsistent
	if len(reasonList) > 0 {
		verdict = VerdictReviewRequired
	}
	return RolloutAssessment{
		ID:               id,
		PlanID:           plan.ID,
		RevisionID:       revision.ID,
		Verdict:          verdict,
		Reasons:          reasonList,
		ProbeCount:       probeCount,
		SuccessCount:     successCount,
		SuccessRatio:     successRatio,
		MaximumLatencyMS: maximumLatency,
		CreatedAt:        now.UTC(),
	}
}

func round(value float64, places int) float64 {
	scale := math.Pow10(places)
	return math.Round(value*scale) / scale
}

func timePointer(value time.Time) *time.Time {
	return &value
}
