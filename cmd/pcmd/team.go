package main

import (
	"fmt"
	"log/slog"
	"time"

	"github.com/spf13/cobra"

	"github.com/pocketcmd/pocketcmd-server/internal/authz"
	"github.com/pocketcmd/pocketcmd-server/internal/config"
	"github.com/pocketcmd/pocketcmd-server/internal/datasync"
	"github.com/pocketcmd/pocketcmd-server/internal/pki"
)

// Mirrors the HTTP handler's cap: invites are bearer credentials, so --expires is clamped rather than rejected.
const maxInviteLifetime = 30 * 24 * time.Hour

// `invite --for` mints a second-device invite for any user, including the owner: deliberate operator-as-root authority the HTTP API does not grant.
func newInviteCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "invite",
		Short: "Create an invite code for a new team member or device",
		Long: `Create an invite: a short code plus a pocketcmd://invite?... URL (and its QR code) that
a teammate enters in the app to join this server. Without --for it creates a new user
with the given --role; with --for it adds another device to an existing user, who keeps
their role. Invites expire after --expires (at most 30 days).

The first device pairs on the first run; invites exist once that owner device is paired.`,
		Example: `  pcmd invite --label "Alice's phone"
  pcmd invite --role admin --expires 48h --label "Bob (backup admin)"
  pcmd invite --for alice --label "Alice's iPad"`,
		Args: cobra.NoArgs,
		RunE: runInvite,
	}
	cmd.Flags().String("for", "", "User ID or display name to add a device for (omit to create a new user)")
	cmd.Flags().String("role", "member", "Role for the invited user (admin|member); ignored when --for is set")
	cmd.Flags().String("pin-device", "", "Require this pubkey fingerprint at redemption (optional)")
	cmd.Flags().Duration("expires", 24*time.Hour, "How long the invite is valid")
	cmd.Flags().String("label", "", "Free-text note (not sent to recipient)")
	addAdvertiseIPFlag(cmd)
	return cmd
}

func newInvitesCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:     "list-invites",
		Aliases: []string{"invites"},
		Short:   "List outstanding invites",
		Long: `List the invites that are still redeemable: code, role, expiry, target (the user ID for
a second-device invite, "(new user)" otherwise) and label.`,
		Example: `  pcmd list-invites
  pcmd list-invites --json`,
		Args: cobra.NoArgs,
		RunE: runInvitesList,
	}
	addJSONFlag(cmd)
	return cmd
}

func newRevokeInviteCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "revoke-invite <code-or-prefix>",
		Short: "Revoke an outstanding invite",
		Long:  `Revoke an invite before it is redeemed. Accepts the full code or an unambiguous prefix.`,
		Example: `  pcmd revoke-invite a1b2c3d4
  pcmd revoke-invite a1b2 --yes`,
		Args: cobra.ExactArgs(1),
		RunE: runRevokeInvite,
	}
	addYesFlag(cmd)
	return cmd
}

func resolveUser(users *pki.UserRegistry, query string) (*pki.UserRecord, error) {
	if u, err := users.FindByID(query); err == nil && u != nil {
		return u, nil
	}
	u, err := users.FindByDisplayName(query)
	if err != nil {
		return nil, err
	}
	if u == nil {
		return nil, fmt.Errorf("user %q not found", query)
	}
	return u, nil
}

var errNoOwner = fmt.Errorf("no owner yet; run `pcmd` first to pair the owner device")

func activeOwner(users *pki.UserRegistry) (*pki.UserRecord, error) {
	all, err := users.List()
	if err != nil {
		return nil, err
	}
	for i := range all {
		if authz.IsOwner(&all[i]) {
			return &all[i], nil
		}
	}
	return nil, errNoOwner
}

func runInvite(cmd *cobra.Command, args []string) error {
	w := cmd.OutOrStdout()
	db, err := stateDB()
	if err != nil {
		return err
	}
	users := pki.NewUserRegistry(db)
	invites := pki.NewInviteStore(db)
	if _, err := activeOwner(users); err != nil {
		return err
	}

	forName, _ := cmd.Flags().GetString("for")
	role, _ := cmd.Flags().GetString("role")
	pinFP, _ := cmd.Flags().GetString("pin-device")
	expires, _ := cmd.Flags().GetDuration("expires")
	label, _ := cmd.Flags().GetString("label")

	if expires > maxInviteLifetime {
		fmt.Fprintf(w, "Note: --expires %s exceeds the maximum invite lifetime; using %s.\n", expires, maxInviteLifetime)
		expires = maxInviteLifetime
	}

	var targetUID string
	if forName != "" {
		u, err := resolveUser(users, forName)
		if err != nil {
			return err
		}
		targetUID = u.UserID
		role = u.Role
	}

	inv, err := invites.Create(pki.CreateInviteParams{
		Role:              role,
		ExpiresIn:         expires,
		TargetUserID:      targetUID,
		PinnedFingerprint: pinFP,
		Label:             label,
		CreatedByUID:      "cli",
	})
	if err != nil {
		return err
	}

	fmt.Fprintf(w, "Invite code: %s\n", inv.Code)
	fmt.Fprintf(w, "Expires:     %s\n", inv.ExpiresAt)
	if targetUID != "" {
		fmt.Fprintf(w, "For user:    %s\n", forName)
	}
	if pinFP != "" {
		fmt.Fprintf(w, "Pinned:      %s\n", pinFP)
	}
	if label != "" {
		fmt.Fprintf(w, "Label:       %s\n", label)
	}

	_, fp, err := pki.LoadOrGenerateServerCert(config.TLSDir())
	if err != nil {
		return fmt.Errorf("load server cert: %w", err)
	}
	port, host, advertiseIP := runtimeSettings(cmd)
	url := inviteURL(resolveAdvertiseIP(advertiseIP, host), port, inv.Code, fp)

	if qr, _ := renderQR(url); qr != "" {
		fmt.Fprintln(w, "\nScan QR in the PocketCmd app to join:")
		fmt.Fprintln(w)
		fmt.Fprint(w, qr)
	}
	fmt.Fprintf(w, "Invite URL:  %s\n", url)

	return nil
}

func runInvitesList(cmd *cobra.Command, args []string) error {
	db, err := stateDB()
	if err != nil {
		return err
	}
	store := pki.NewInviteStore(db)
	active, err := store.ListActive()
	if err != nil {
		return err
	}
	if jsonFlag(cmd) {
		if active == nil {
			active = []pki.InviteRecord{}
		}
		return writeJSON(cmd.OutOrStdout(), active)
	}
	if len(active) == 0 {
		fmt.Fprintln(cmd.OutOrStdout(), "No active invites.")
		return nil
	}
	fmt.Fprintf(cmd.OutOrStdout(), "%-16s  %-6s  %-20s  %-14s  %s\n", "CODE", "ROLE", "EXPIRES", "TARGET", "LABEL")
	for _, inv := range active {
		target := "(new user)"
		if inv.TargetUserID != "" {
			target = inv.TargetUserID
		}
		fmt.Fprintf(cmd.OutOrStdout(), "%-16s  %-6s  %-20s  %-14s  %s\n",
			inv.Code, inv.Role, inv.ExpiresAt, target, inv.Label)
	}
	return nil
}

func runRevokeInvite(cmd *cobra.Command, args []string) error {
	db, err := stateDB()
	if err != nil {
		return err
	}
	store := pki.NewInviteStore(db)
	inv, err := store.FindByPrefix(args[0])
	if err != nil {
		return err
	}
	if inv == nil {
		return fmt.Errorf("no invite matching %q", args[0])
	}
	yes, nonInteractive := guardFlags(cmd)
	ok, err := confirmDestructive(cmd.OutOrStdout(), "revoke the invite",
		fmt.Sprintf("Revoke invite %s?", inv.Code), yes, nonInteractive)
	if err != nil || !ok {
		return err
	}
	if err := store.Revoke(inv.Code, "cli"); err != nil {
		return err
	}
	fmt.Fprintf(cmd.OutOrStdout(), "Revoked invite %s\n", inv.Code)
	return nil
}

func newListUsersCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "list-users",
		Short: "List team members",
		Long:  `List every team member with user ID, display name, role (owner, admin or member), status and active device count.`,
		Example: `  pcmd list-users
  pcmd list-users --json`,
		Args: cobra.NoArgs,
		RunE: runListUsers,
	}
	addJSONFlag(cmd)
	return cmd
}

type userRow struct {
	UserID      string            `json:"user_id"`
	DisplayName string            `json:"display_name"`
	Role        string            `json:"role"`
	Owner       bool              `json:"owner"`
	Status      string            `json:"status"`
	Devices     int               `json:"active_devices"`
	Permissions pki.PermissionSet `json:"permissions,omitempty"`
}

func newRevokeUserCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "revoke-user <user-or-name>",
		Short: "Revoke a team member (cascades to devices and outstanding invites)",
		Long: `Revoke a team member: their devices are revoked, the invites made for or by them are
cancelled and their vault access is removed. Takes effect on the member's next request. The owner and the last active
admin cannot be revoked. --purge-data additionally deletes the sync records their
devices wrote (tombstoned, so the remaining devices sync the deletion).`,
		Example: `  pcmd revoke-user bob
  pcmd revoke-user k7f3m9q2w8xz --purge-data --yes`,
		Args: cobra.ExactArgs(1),
		RunE: runRevokeUser,
	}
	cmd.Flags().Bool("purge-data", false, "Also hard-delete the sync data written by the user's devices")
	addYesFlag(cmd)
	return cmd
}

func runListUsers(cmd *cobra.Command, args []string) error {
	db, err := stateDB()
	if err != nil {
		return err
	}
	users := pki.NewUserRegistry(db)
	devs := pki.NewDeviceRegistry(db)

	all, err := users.List()
	if err != nil {
		return err
	}
	rows := make([]userRow, 0, len(all))
	for _, u := range all {
		userDevs, _ := devs.DevicesByUserID(u.UserID)
		active := 0
		for _, d := range userDevs {
			if d.Status == "active" {
				active++
			}
		}
		role := u.Role
		if u.Owner {
			role = "owner"
		}
		rows = append(rows, userRow{UserID: u.UserID, DisplayName: u.DisplayName, Role: role, Owner: u.Owner,
			Status: u.Status, Devices: active, Permissions: u.Permissions})
	}
	if jsonFlag(cmd) {
		return writeJSON(cmd.OutOrStdout(), rows)
	}
	if len(rows) == 0 {
		fmt.Fprintln(cmd.OutOrStdout(), "No users.")
		return nil
	}

	fmt.Fprintf(cmd.OutOrStdout(), "%-14s  %-20s  %-8s  %-8s  %-8s\n", "USER_ID", "NAME", "ROLE", "STATUS", "DEVICES")
	for _, r := range rows {
		fmt.Fprintf(cmd.OutOrStdout(), "%-14s  %-20s  %-8s  %-8s  %d\n",
			r.UserID, r.DisplayName, r.Role, r.Status, r.Devices)
	}
	return nil
}

func newPromoteCmd() *cobra.Command {
	return &cobra.Command{
		Use:     "promote <user-or-name>",
		Short:   "Promote a member to admin",
		Long:    `Make a member an admin. Admins hold every permission except metrics.commands.create, which they keep only if it was granted; other member grants are ignored for them.`,
		Example: `  pcmd promote bob`,
		Args:    cobra.ExactArgs(1),
		RunE:    runPromote,
	}
}

func newDemoteCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "demote <user-or-name>",
		Short: "Demote an admin to member",
		Long:  `Make an admin a member again. The owner and the last active admin cannot be demoted.`,
		Example: `  pcmd demote bob
  pcmd demote bob --yes`,
		Args: cobra.ExactArgs(1),
		RunE: runDemote,
	}
	addYesFlag(cmd)
	return cmd
}

func runPromote(cmd *cobra.Command, args []string) error {
	db, err := stateDB()
	if err != nil {
		return err
	}
	users := pki.NewUserRegistry(db)
	u, err := resolveUser(users, args[0])
	if err != nil {
		return err
	}
	if u.Role == "admin" {
		fmt.Fprintf(cmd.OutOrStdout(), "%s is already an admin.\n", u.DisplayName)
		return nil
	}
	if err := users.SetRole(u.UserID, "admin"); err != nil {
		return err
	}
	fmt.Fprintf(cmd.OutOrStdout(), "Promoted %s to admin.\n", u.DisplayName)
	return nil
}

func runDemote(cmd *cobra.Command, args []string) error {
	db, err := stateDB()
	if err != nil {
		return err
	}
	users := pki.NewUserRegistry(db)
	u, err := resolveUser(users, args[0])
	if err != nil {
		return err
	}
	if u.Role == "member" {
		fmt.Fprintf(cmd.OutOrStdout(), "%s is already a member.\n", u.DisplayName)
		return nil
	}
	// Demoting the owner would leave an IsOwner-passing record with no admin surface; no force flag on purpose.
	if u.Owner {
		return fmt.Errorf("refusing: the owner cannot be demoted")
	}
	if u.Status == "active" {
		n, err := users.CountActiveAdmins()
		if err != nil {
			return err
		}
		if n <= 1 {
			return fmt.Errorf("refusing: %s is the last active admin", u.DisplayName)
		}
	}
	yes, nonInteractive := guardFlags(cmd)
	ok, err := confirmDestructive(cmd.OutOrStdout(), "demote the admin",
		fmt.Sprintf("Demote %s to member?", u.DisplayName), yes, nonInteractive)
	if err != nil || !ok {
		return err
	}
	// The count above is check-then-act; SetRoleGuarded re-checks inside the UPDATE.
	applied, err := users.SetRoleGuarded(u.UserID, "member")
	if err != nil {
		return err
	}
	if !applied {
		return fmt.Errorf("refusing: %s is the last active admin", u.DisplayName)
	}
	fmt.Fprintf(cmd.OutOrStdout(), "Demoted %s to member.\n", u.DisplayName)
	return nil
}

func runRevokeUser(cmd *cobra.Command, args []string) error {
	purgeData, _ := cmd.Flags().GetBool("purge-data")

	db, err := stateDB()
	if err != nil {
		return err
	}
	users := pki.NewUserRegistry(db)
	devs := pki.NewDeviceRegistry(db)
	invites := pki.NewInviteStore(db)

	u, err := resolveUser(users, args[0])
	if err != nil {
		return err
	}

	// Revoking the owner would strand an IsOwner-passing record with no admin surface; no force flag on purpose.
	if u.Owner {
		return fmt.Errorf("refusing: the owner cannot be removed")
	}

	if u.Role == "admin" && u.Status == "active" {
		n, err := users.CountActiveAdmins()
		if err != nil {
			return err
		}
		if n <= 1 {
			return fmt.Errorf("refusing: %s is the last active admin", u.DisplayName)
		}
	}

	question := fmt.Sprintf("Revoke %s and all of their devices and invites?", u.DisplayName)
	if purgeData {
		question = fmt.Sprintf("Revoke %s, all of their devices and invites, AND permanently delete the sync data their devices wrote?", u.DisplayName)
	}
	yes, nonInteractive := guardFlags(cmd)
	ok, err := confirmDestructive(cmd.OutOrStdout(), "revoke the user", question, yes, nonInteractive)
	if err != nil || !ok {
		return err
	}

	// The count above is check-then-act; RevokeGuarded re-checks inside the UPDATE.
	applied, err := users.RevokeGuarded(u.UserID)
	if err != nil {
		return err
	}
	if !applied {
		return fmt.Errorf("refusing: %s is the last active admin", u.DisplayName)
	}

	userDevs, _ := devs.DevicesByUserID(u.UserID)
	for _, d := range userDevs {
		if d.Status != "active" {
			continue
		}
		_ = devs.Revoke(d.DeviceID)
	}

	// Invites the user created are revoked too: a credential minted by a removed member must not outlive its issuer's authority.
	active, _ := invites.ListActive()
	for _, inv := range active {
		if inv.TargetUserID == u.UserID || inv.CreatedByUserID == u.UserID {
			_ = invites.Revoke(inv.Code, "cli")
		}
	}

	store := datasync.NewSyncStore(db, nil)
	vaults, err := store.VaultsForUser(u.UserID)
	if err != nil {
		return fmt.Errorf("list vault access: %w", err)
	}
	if err := withAudit(func(audit *slog.Logger) error {
		for _, vaultID := range vaults {
			if err := store.RevokeVault(vaultID, u.UserID); err != nil {
				return fmt.Errorf("revoke vault %s: %w", vaultID, err)
			}
			audit.Info("vault_revoked",
				"user_id", cliActor, "vault_id", vaultID,
				"target_user", u.UserID, "level", "")
		}
		return nil
	}); err != nil {
		return err
	}

	fmt.Fprintf(cmd.OutOrStdout(), "Revoked user %s (%s)\n", u.DisplayName, u.UserID)
	if len(vaults) > 0 {
		fmt.Fprintf(cmd.OutOrStdout(), "Removed their access to %d vault(s).\n", len(vaults))
	}
	if purgeData {
		deviceIDs := make([]string, 0, len(userDevs))
		for _, d := range userDevs {
			deviceIDs = append(deviceIDs, d.DeviceID)
		}
		n, err := store.PurgeUserData(u.UserID, deviceIDs)
		if err != nil {
			return fmt.Errorf("purge sync data: %w", err)
		}
		fmt.Fprintf(cmd.OutOrStdout(), "Purged %d sync record(s) written by %s's devices.\n", n, u.DisplayName)
	}
	return nil
}
