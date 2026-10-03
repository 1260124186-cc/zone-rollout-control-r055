package store

import "solo-0014-zone-rollout-control/internal/domain"

const schemaVersion = 1

func blankState() domain.State {
	return normalize(domain.State{})
}

func normalize(state domain.State) domain.State {
	if state.SchemaVersion == 0 {
		state.SchemaVersion = schemaVersion
	}
	if state.Plans == nil {
		state.Plans = make(map[string]domain.RolloutPlan)
	}
	if state.Revisions == nil {
		state.Revisions = make(map[string]domain.ZoneRevision)
	}
	if state.Nodes == nil {
		state.Nodes = make(map[string]domain.ResolverNode)
	}
	if state.Leases == nil {
		state.Leases = make(map[string]domain.NodeLease)
	}
	if state.LeaseGroups == nil {
		state.LeaseGroups = make(map[string]domain.LeaseGroup)
	}
	if state.Probes == nil {
		state.Probes = make(map[string]domain.Probe)
	}
	if state.Assessments == nil {
		state.Assessments = make(map[string]domain.RolloutAssessment)
	}
	if state.LeaseRequestKeys == nil {
		state.LeaseRequestKeys = make(map[string]string)
	}
	if state.AssessmentRequestKeys == nil {
		state.AssessmentRequestKeys = make(map[string]string)
	}
	if state.AuditEvents == nil {
		state.AuditEvents = []domain.AuditEvent{}
	}
	if state.NodeAdmissions == nil {
		state.NodeAdmissions = make(map[string]domain.NodeAdmission)
	}
	// Quarantine is a durable admission decision. Older snapshots could contain
	// a quarantined node whose admission record was never marked accordingly;
	// reconcile those records so the decision survives lease lifecycle events
	// and process restarts.
	for _, node := range state.Nodes {
		if node.State != domain.NodeQuarantined {
			continue
		}
		admission := state.NodeAdmissions[node.ID]
		if admission.Quarantined {
			continue
		}
		admission.NodeID = node.ID
		if admission.NodeName == "" {
			admission.NodeName = node.NodeName
		}
		if admission.Region == "" {
			admission.Region = node.Region
		}
		if admission.RecordedAt.IsZero() {
			admission.RecordedAt = node.UpdatedAt
		}
		admission.Quarantined = true
		state.NodeAdmissions[node.ID] = admission
	}
	return state
}
