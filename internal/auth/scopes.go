package auth

import "github.com/rootxkit/uspace-cisp/internal/publication"

// The machine scopes the CISP checks (docs/PLAN.md section 8.2). The
// catalogue is held by the authority (M23); a new cis.* scope is a pull
// request there first.
const (
	ScopeRead                = "cis.read"
	ScopePublishZones        = "cis.publish:zones"
	ScopePublishUSpace       = "cis.publish:uspace"
	ScopePublishUSSPList     = "cis.publish:ussp_list"
	ScopePublishRestrictions = "cis.publish:restrictions"
)

// PublishScope is the scope that publishes dataset, and false for a
// value that is not one of the four datasets.
func PublishScope(dataset publication.Dataset) (string, bool) {
	s, ok := publishScopes[dataset]
	return s, ok
}

var publishScopes = map[publication.Dataset]string{
	publication.DatasetZones:          ScopePublishZones,
	publication.DatasetUSpaceAirspace: ScopePublishUSpace,
	publication.DatasetUSSPList:       ScopePublishUSSPList,
	publication.DatasetRestrictions:   ScopePublishRestrictions,
}

// PublisherOf is the publisher of dataset (F1: the authority; F2: the
// ANSP), and false for a value that is not one of the four datasets.
func PublisherOf(dataset publication.Dataset) (Publisher, bool) {
	switch dataset {
	case publication.DatasetZones, publication.DatasetUSpaceAirspace, publication.DatasetUSSPList:
		return PublisherAuthority, true
	case publication.DatasetRestrictions:
		return PublisherANSP, true
	}
	return "", false
}

// Publisher is a calling system that may publish: the authority (F1) or
// the ANSP (F2).
type Publisher string

// The two publishers.
const (
	PublisherAuthority Publisher = "authority"
	PublisherANSP      Publisher = "ansp"
)
