package publication

import "strconv"

// Dataset is one of the four published datasets.
type Dataset string

// The datasets (docs/PLAN.md section 5.1, the datasets table).
const (
	DatasetZones          Dataset = "zones"
	DatasetUSpaceAirspace Dataset = "uspace_airspace"
	DatasetUSSPList       Dataset = "ussp_list"
	DatasetRestrictions   Dataset = "restrictions"
)

// Datasets is every dataset, in the order the plan lists them.
var Datasets = []Dataset{DatasetZones, DatasetUSpaceAirspace, DatasetUSSPList, DatasetRestrictions}

// Valid reports whether d is one of the four datasets.
func (d Dataset) Valid() bool {
	switch d {
	case DatasetZones, DatasetUSpaceAirspace, DatasetUSSPList, DatasetRestrictions:
		return true
	}
	return false
}

// Kind is the content kind of a dataset.
type Kind string

// The kinds.
const (
	// KindED318 is an ED-318 FeatureCollection of UASZone features.
	KindED318 Kind = "ed318"
	// KindUsspList is cis/ussp_list/v1.
	KindUsspList Kind = "ussp_list"
)

// Kind is the dataset's content kind: ussp_list is the USSP list, every
// other dataset is ED-318 (D4: restrictions too).
func (d Dataset) Kind() Kind {
	if d == DatasetUSSPList {
		return KindUsspList
	}
	return KindED318
}

// Reason is why a version or a change record exists.
type Reason string

// The reasons (docs/PLAN.md sections 5.1 and 6.7).
const (
	ReasonPublication          Reason = "publication"
	ReasonRestrictionCreated   Reason = "restriction_created"
	ReasonRestrictionActivated Reason = "restriction_activated"
	ReasonRestrictionExtended  Reason = "restriction_extended"
	ReasonRestrictionEnded     Reason = "restriction_ended"
	ReasonRestrictionCancelled Reason = "restriction_cancelled"
	ReasonRestrictionExpired   Reason = "restriction_expired"
	ReasonRepublished          Reason = "republished"
	// ReasonSubscriptionTest is a change record only, never a version.
	ReasonSubscriptionTest Reason = "subscription_test"
)

// VersionReason reports whether r may be the reason of a version (every
// reason but subscription_test).
func (r Reason) VersionReason() bool {
	switch r {
	case ReasonPublication, ReasonRestrictionCreated, ReasonRestrictionActivated,
		ReasonRestrictionExtended, ReasonRestrictionEnded, ReasonRestrictionCancelled,
		ReasonRestrictionExpired, ReasonRepublished:
		return true
	case ReasonSubscriptionTest:
		return false
	}
	return false
}

// ETag is the entity tag of a dataset version, quotes included:
// `"zones:12"` (02 F3: the ETag is the version).
func ETag(dataset Dataset, version int64) string {
	return `"` + string(dataset) + ":" + strconv.FormatInt(version, 10) + `"`
}
