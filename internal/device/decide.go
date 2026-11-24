package device

import (
	"context"
	"fmt"
	"net/netip"
	"uuid"

	"github.com/the-asmit/nook/internal/apperr"
	"github.com/the-asmit/nook/internal/audit"
	"github.com/the-asmit/nook/internal/auth"
	"github.com/the-asmit/nook/internal/store"
)

// errUnknownCode is deliberately vague: it does not say whether a code
// never existed, expired or was already used.
func errUnknownCode() error {
	return apperr.NotFound("that code is not valid; check it, or start again on the device")
}

// Lookup returns the pending request for a code a signed-in person typed.
func (s *Service) Lookup(ctx context.Context, userCode string) (store.DeviceAuthorization, error) {
	code, err := auth.NormalizeUserCode(userCode)
	if err != nil {
		return store.DeviceAuthorization{}, errUnknownCode()
	}
	d, err := s.store.GetPendingDeviceAuthorization(ctx, code)
	if store.IsNotFound(err) {
		return store.DeviceAuthorization{}, errUnknownCode()
	}
	if err != nil {
		return store.DeviceAuthorization{}, fmt.Errorf("look up device authorization: %w", err)
	}
	return d, nil
}

// Decide approves or denies a pending request on behalf of userID. Only
// pending, unexpired requests can be decided, and only once.
func (s *Service) Decide(ctx context.Context, userID uuid.UUID, ip *netip.Addr, userCode string, approve bool) (store.DeviceAuthorization, error) {
	code, err := auth.NormalizeUserCode(userCode)
	if err != nil {
		return store.DeviceAuthorization{}, errUnknownCode()
	}
	status, action := store.DeviceStatusDenied, audit.ActionDeviceDeny
	if approve {
		status, action = store.DeviceStatusApproved, audit.ActionDeviceApprove
	}
	var d store.DeviceAuthorization
	err = s.store.InTx(ctx, func(q *store.Queries) error {
		d, err = q.DecideDeviceAuthorization(ctx, store.DecideDeviceAuthorizationParams{
			UserCode: code, Status: status, UserID: &userID,
		})
		if store.IsNotFound(err) {
			return errUnknownCode()
		}
		if err != nil {
			return fmt.Errorf("decide device authorization: %w", err)
		}
		return audit.Record(ctx, q, &audit.Entry{
			ActorID: &userID, IP: ip,
			Action: action, TargetType: audit.TargetDevice, TargetID: d.ID.String(),
			Metadata: map[string]any{"client_name": d.ClientName},
		})
	})
	return d, err
}
