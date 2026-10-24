package server

import (
	"context"
	"fmt"
	"net/http"

	"github.com/pocketcmd/pocketcmd-server/internal/authz"
	"github.com/pocketcmd/pocketcmd-server/internal/httperr"
	"github.com/pocketcmd/pocketcmd-server/internal/pki"
)

const (
	contextKeyUserID contextKey = "user_id"
	contextKeyRole   contextKey = "role"
	contextKeyUser   contextKey = "user_record"
)

func ResolveUser(deviceID string, devs *pki.DeviceRegistry, users *pki.UserRegistry) (*pki.UserRecord, error) {
	dev, err := devs.FindByID(deviceID)
	if err != nil {
		return nil, err
	}
	if dev == nil {
		return nil, fmt.Errorf("device not found")
	}
	if dev.Status != pki.DeviceStatusActive {
		return nil, fmt.Errorf("device not active (%s)", dev.Status)
	}
	if dev.UserID == "" {
		return nil, fmt.Errorf("device has no user binding")
	}
	u, err := users.FindByID(dev.UserID)
	if err != nil {
		return nil, err
	}
	if u == nil || u.Status != pki.UserStatusActive {
		return nil, fmt.Errorf("user not active")
	}
	return u, nil
}

func callerFrom(r *http.Request) *pki.UserRecord {
	u, _ := r.Context().Value(contextKeyUser).(*pki.UserRecord)
	return u
}

func callerIDFrom(r *http.Request) string {
	id, _ := r.Context().Value(contextKeyUserID).(string)
	return id
}

func deviceIDFrom(r *http.Request) string {
	id, _ := r.Context().Value(contextKeyDeviceID).(string)
	return id
}

func RequirePermission(perm string, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !authz.Allowed(callerFrom(r), perm) {
			httperr.JSON(w, http.StatusForbidden, "permission_required")
			return
		}
		next.ServeHTTP(w, r)
	})
}

func RequireRole(required string, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		role, _ := r.Context().Value(contextKeyRole).(string)
		if role != required {
			httperr.JSON(w, http.StatusForbidden, "forbidden")
			return
		}
		next.ServeHTTP(w, r)
	})
}

func RequireOwner(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !authz.IsOwner(callerFrom(r)) {
			httperr.JSON(w, http.StatusForbidden, "owner_required")
			return
		}
		next.ServeHTTP(w, r)
	})
}

func withUserContext(ctx context.Context, u *pki.UserRecord) context.Context {
	ctx = context.WithValue(ctx, contextKeyUserID, u.UserID)
	ctx = context.WithValue(ctx, contextKeyRole, u.Role)
	return context.WithValue(ctx, contextKeyUser, u)
}
