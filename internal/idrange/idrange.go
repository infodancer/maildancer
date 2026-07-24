// Package idrange defines the boundary between reserved system ids and the
// allocated user/domain id space. It is the single home for the constants
// that were previously duplicated as literals in auth/identity (the
// allocator floor) and internal/admin (the reserved-gid ceiling), and it is
// importable by the protocol daemons, which depguard bars from importing
// auth directly.
//
// The id space splits three ways:
//
//   - [1, AllocatorFloor): reserved for system/service accounts -- the
//     all-in-one image's fixed accounts (mailsvc 900 ... cfgread 906) and
//     anything else an operator assigns by hand (e.g. protocol-handler
//     credentials).
//   - [AllocatorFloor, ExcludedBandLow) and (ExcludedBandHigh, MaxUint32]:
//     the allocatable space. The shared uid/gid counter hands ids out from
//     here, and only these values may appear in the identity maps
//     (gid.toml / uid.toml).
//   - [ExcludedBandLow, ExcludedBandHigh]: well-known ids that must never
//     be allocated -- 65532 (distroless nonroot, which legacy trees grant
//     access to; see internal/admin), 65533 (nogroup), 65534 (nobody),
//     65535 (the 16-bit -1, rejected by some interfaces).
//
// Zero is none of these: it is root/"unset" and valid nowhere.
package idrange

import "fmt"

// AllocatorFloor is the first id the shared uid/gid allocator hands out.
// Everything below it is reserved for system/service accounts.
const AllocatorFloor uint32 = 10000

// ExcludedBandLow..ExcludedBandHigh is the well-known top band the
// allocator skips: distroless nonroot/nogroup, nobody, and the 16-bit -1.
const (
	ExcludedBandLow  uint32 = 65532
	ExcludedBandHigh uint32 = 65535
)

// Allocatable reports whether id may be handed out by the allocator and
// therefore may legitimately appear in the identity maps. Spawning code
// must refuse credentials for which this is false.
func Allocatable(id uint32) bool {
	return id >= AllocatorFloor && (id < ExcludedBandLow || id > ExcludedBandHigh)
}

// Reserved reports whether id is a nonzero id outside the allocatable
// space -- the only values acceptable for service credentials such as the
// daemons' handler_uid/handler_gid, where colliding with an allocated user
// or domain id would grant the internet-facing handler that principal's
// filesystem rights.
func Reserved(id uint32) bool {
	return id != 0 && !Allocatable(id)
}

// CheckHandlerIDs validates the handler_uid/handler_gid/handler_groups
// credential set shared by the protocol daemons' configs: every nonzero id
// must be Reserved. An allocated user or domain id here would run the
// internet-facing protocol handler with that principal's filesystem rights,
// silently undoing the privilege separation.
func CheckHandlerIDs(uid, gid uint32, groups []uint32) error {
	if uid != 0 && !Reserved(uid) {
		return fmt.Errorf("handler_uid %d is in the allocatable user/domain id range; use a reserved service id (below %d, or %d-%d)", uid, AllocatorFloor, ExcludedBandLow, ExcludedBandHigh)
	}
	if gid != 0 && !Reserved(gid) {
		return fmt.Errorf("handler_gid %d is in the allocatable user/domain id range; use a reserved service id (below %d, or %d-%d)", gid, AllocatorFloor, ExcludedBandLow, ExcludedBandHigh)
	}
	for _, g := range groups {
		if !Reserved(g) {
			return fmt.Errorf("handler_groups entry %d is zero or in the allocatable user/domain id range; use reserved service ids (below %d, or %d-%d)", g, AllocatorFloor, ExcludedBandLow, ExcludedBandHigh)
		}
	}
	return nil
}
