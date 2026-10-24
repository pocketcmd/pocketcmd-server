package main

import (
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/spf13/cobra"

	"github.com/pocketcmd/pocketcmd-server/internal/authz"
	"github.com/pocketcmd/pocketcmd-server/internal/config"
	"github.com/pocketcmd/pocketcmd-server/internal/datasync"
	"github.com/pocketcmd/pocketcmd-server/internal/metrics"
	"github.com/pocketcmd/pocketcmd-server/internal/monitoring"
	"github.com/pocketcmd/pocketcmd-server/internal/pki"
)

const cliActor = "cli"

func withAudit(fn func(audit *slog.Logger) error) error {
	audit, cleanup := setupAuditLogger()
	defer cleanup()
	return fn(audit)
}

func newVaultsCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "vaults",
		Short: "List shared vaults with their member counts",
		Long: `List every shared vault the server knows (through its access list) and how many members
hold access. Vault contents are ciphertext the server cannot read; only the IDs and
membership are visible here.`,
		Example: `  pcmd vaults
  pcmd vaults --json`,
		Args: cobra.NoArgs,
		RunE: runVaults,
	}
	addJSONFlag(cmd)
	return cmd
}

func runVaults(cmd *cobra.Command, args []string) error {
	db, err := stateDB()
	if err != nil {
		return err
	}
	vaults, err := datasync.NewSyncStore(db, nil).ListVaults()
	if err != nil {
		return err
	}
	w := cmd.OutOrStdout()
	if jsonFlag(cmd) {
		if vaults == nil {
			vaults = []datasync.VaultSummary{}
		}
		return writeJSON(w, vaults)
	}
	if len(vaults) == 0 {
		fmt.Fprintln(w, "No shared vaults.")
		return nil
	}
	fmt.Fprintf(w, "%-40s  %s\n", "VAULT_ID", "MEMBERS")
	for _, v := range vaults {
		fmt.Fprintf(w, "%-40s  %d\n", v.VaultID, v.Members)
	}
	return nil
}

type vaultMemberRow struct {
	UserID      string `json:"user_id"`
	DisplayName string `json:"display_name,omitempty"`
	Role        string `json:"role,omitempty"`
	Level       string `json:"level"`
}

func newVaultMembersCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:     "vault-members <vault-id>",
		Short:   "List the members of a shared vault and their access level",
		Long:    `List who has access to a vault and at which level (view, edit or manage).`,
		Example: `  pcmd vault-members 3f9c…`,
		Args:    cobra.ExactArgs(1),
		RunE:    runVaultMembers,
	}
	addJSONFlag(cmd)
	return cmd
}

func runVaultMembers(cmd *cobra.Command, args []string) error {
	db, err := stateDB()
	if err != nil {
		return err
	}
	store := datasync.NewSyncStore(db, nil)
	if !store.VaultExists(args[0]) {
		return fmt.Errorf("vault %q not found (see `pcmd vaults`)", args[0])
	}
	members, err := store.VaultMembers(args[0])
	if err != nil {
		return err
	}
	users := pki.NewUserRegistry(db)
	rows := make([]vaultMemberRow, 0, len(members))
	for _, m := range members {
		row := vaultMemberRow{UserID: m.UserID, Level: m.Level}
		if u, _ := users.FindByID(m.UserID); u != nil {
			row.DisplayName = u.DisplayName
			row.Role = u.Role
			if u.Owner {
				row.Role = "owner"
			}
		}
		rows = append(rows, row)
	}
	w := cmd.OutOrStdout()
	if jsonFlag(cmd) {
		return writeJSON(w, rows)
	}
	fmt.Fprintf(w, "%-14s  %-20s  %-8s  %s\n", "USER_ID", "NAME", "ROLE", "LEVEL")
	for _, r := range rows {
		name, role := r.DisplayName, r.Role
		if name == "" {
			name = "-"
		}
		if role == "" {
			role = "-"
		}
		fmt.Fprintf(w, "%-14s  %-20s  %-8s  %s\n", r.UserID, name, role, r.Level)
	}
	return nil
}

func newRenameUserCmd() *cobra.Command {
	return &cobra.Command{
		Use:     "rename-user <user-or-name> <new-display-name>",
		Short:   "Change a team member's display name",
		Long:    `Change the display name shown for a team member in the app and in this CLI. The change is recorded in the audit log.`,
		Example: `  pcmd rename-user bob "Bob Smith"`,
		Args:    cobra.ExactArgs(2),
		RunE:    runRenameUser,
	}
}

func runRenameUser(cmd *cobra.Command, args []string) error {
	newName := strings.TrimSpace(args[1])
	if newName == "" {
		return fmt.Errorf("the new display name must not be empty")
	}
	db, err := stateDB()
	if err != nil {
		return err
	}
	users := pki.NewUserRegistry(db)
	u, err := resolveUser(users, args[0])
	if err != nil {
		return err
	}
	if u.DisplayName == newName {
		fmt.Fprintf(cmd.OutOrStdout(), "%s is already named %q.\n", u.UserID, newName)
		return nil
	}
	return withAudit(func(audit *slog.Logger) error {
		if err := users.SetDisplayName(u.UserID, newName); err != nil {
			return err
		}
		audit.Info("user_renamed",
			"user_id", u.UserID,
			"old_name", u.DisplayName,
			"new_name", newName,
			"changed_by", cliActor,
		)
		fmt.Fprintf(cmd.OutOrStdout(), "Renamed %s to %s.\n", u.DisplayName, newName)
		return nil
	})
}

func newTransferOwnershipCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "transfer-ownership <user-or-name>",
		Short: "Make another active member the owner",
		Long: `Hand the owner role to another active team member. The new owner becomes an admin with
the owner flag; the previous owner stays an admin. The swap is atomic, so there is always
exactly one owner, and it applies to the running service at once (owner-only routes and
the vault access override resolve the flag per request). Recorded in the audit log as
owner_transferred.`,
		Example: `  pcmd transfer-ownership bob
  pcmd transfer-ownership k7f3m9q2w8xz --yes`,
		Args: cobra.ExactArgs(1),
		RunE: runTransferOwnership,
	}
	addYesFlag(cmd)
	return cmd
}

func runTransferOwnership(cmd *cobra.Command, args []string) error {
	db, err := stateDB()
	if err != nil {
		return err
	}
	users := pki.NewUserRegistry(db)
	owner, err := activeOwner(users)
	if err != nil {
		return err
	}
	target, err := resolveUser(users, args[0])
	if err != nil {
		return err
	}
	// Mirror the HTTP handler's checks before asking, so the prompt never precedes a refusal.
	if target.UserID == owner.UserID {
		return fmt.Errorf("%s is already the owner", target.DisplayName)
	}
	if target.Status != "active" {
		return fmt.Errorf("refusing: %s is %s; only an active member can become the owner", target.DisplayName, target.Status)
	}
	yes, nonInteractive := guardFlags(cmd)
	ok, err := confirmDestructive(cmd.OutOrStdout(), "transfer ownership",
		fmt.Sprintf("Transfer ownership from %s to %s? %s stays an admin.", owner.DisplayName, target.DisplayName, owner.DisplayName),
		yes, nonInteractive)
	if err != nil || !ok {
		return err
	}
	return withAudit(func(audit *slog.Logger) error {
		switch err := users.TransferOwnership(owner.UserID, target.UserID); {
		case err == nil:
		case errors.Is(err, pki.ErrSelfTransfer):
			return fmt.Errorf("%s is already the owner", target.DisplayName)
		case errors.Is(err, pki.ErrUserNotActive):
			return fmt.Errorf("refusing: %s is not active", target.DisplayName)
		case errors.Is(err, pki.ErrNotOwner):
			return fmt.Errorf("%s is no longer the owner; run `pcmd list-users` and try again", owner.DisplayName)
		default:
			return err
		}
		audit.Info("owner_transferred",
			"previous_owner", owner.UserID,
			"new_owner", target.UserID,
			"changed_by", cliActor,
		)
		fmt.Fprintf(cmd.OutOrStdout(), "Transferred ownership from %s to %s; %s stays an admin.\n",
			owner.DisplayName, target.DisplayName, owner.DisplayName)
		return nil
	})
}

func newRenameDeviceCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "rename-device <fingerprint-prefix>",
		Short: "Change a paired device's name or label",
		Long: fmt.Sprintf(`Change the name and/or label of a paired device. The argument is a prefix (8+ characters)
of the device's public key fingerprint or device ID as shown by 'pcmd list-devices'.
Pass --name, --label or both; each is at most %d characters. The change is recorded in
the audit log as device_renamed.`, pki.MaxDeviceNameLen),
		Example: `  pcmd rename-device a1b2c3d4 --name "Alice's iPhone"
  pcmd rename-device a1b2c3d4 --label pocket
  pcmd rename-device a1b2c3d4 --name "Work phone" --label ""`,
		Args: cobra.ExactArgs(1),
		RunE: runRenameDevice,
	}
	cmd.Flags().String("name", "", "New device name")
	cmd.Flags().String("label", "", "New device label (an empty value clears it)")
	return cmd
}

func runRenameDevice(cmd *cobra.Command, args []string) error {
	flags := cmd.Flags()
	var name, label *string
	if flags.Changed("name") {
		v, _ := flags.GetString("name")
		if strings.TrimSpace(v) == "" {
			return fmt.Errorf("the device name must not be empty")
		}
		name = &v
	}
	if flags.Changed("label") {
		v, _ := flags.GetString("label")
		label = &v
	}
	if name == nil && label == nil {
		return fmt.Errorf("nothing to change: pass --name and/or --label")
	}
	for _, v := range []*string{name, label} {
		if v != nil && !pki.ValidDeviceName(*v) {
			return fmt.Errorf("names and labels are at most %d characters", pki.MaxDeviceNameLen)
		}
	}
	db, err := stateDB()
	if err != nil {
		return err
	}
	registry := pki.NewDeviceRegistry(db)
	dev, err := registry.FindByPubKeyPrefix(args[0])
	if err != nil {
		return err
	}
	return withAudit(func(audit *slog.Logger) error {
		if err := registry.Rename(dev.DeviceID, name, label); err != nil {
			if errors.Is(err, pki.ErrNameTooLong) {
				return fmt.Errorf("names and labels are at most %d characters", pki.MaxDeviceNameLen)
			}
			return err
		}
		newName, newLabel := dev.DeviceName, dev.DeviceLabel
		if name != nil {
			newName = *name
		}
		if label != nil {
			newLabel = *label
		}
		audit.Info("device_renamed",
			"device_id", dev.DeviceID,
			"user_id", dev.UserID,
			"old_name", dev.DeviceName,
			"new_name", newName,
			"old_label", dev.DeviceLabel,
			"new_label", newLabel,
			"changed_by", cliActor,
		)
		w := cmd.OutOrStdout()
		if newLabel != "" {
			fmt.Fprintf(w, "Renamed device %s to %q (label %q).\n", dev.DeviceID, newName, newLabel)
		} else {
			fmt.Fprintf(w, "Renamed device %s to %q.\n", dev.DeviceID, newName)
		}
		return nil
	})
}

func permissionKeys() []string {
	keys := make([]string, 0, len(authz.KnownPermissions))
	for k := range authz.KnownPermissions {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

func newGrantCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "grant <user-or-name> <permission>",
		Short: "Grant a permission to a member or admin",
		Long: `Grant a member or an admin one permission. Admins hold every permission
implicitly except metrics.commands.create, so other grants apply to members only.
metrics.commands.create approves metric commands, which then run on this host: the owner
holds it, and an admin or a member holds it only when it is granted. In the app only the
owner can grant it; this command runs on the server host, which is the owner's machine,
so it grants it too; granting it hands the user code execution on this host.
Permission keys:

  ` + strings.Join(permissionKeys(), "\n  ") + `

alerts.read may be limited to specific metric IDs with --metrics (custom:<request-id>, as
listed by the app's dashboard card editor); without it the member receives alerts for
every metric.`,
		Example: `  pcmd grant bob invites.manage
  pcmd grant bob alerts.read --metrics custom:req-1a2b3c4d5e6f7a8b
  pcmd grant alice metrics.commands.create`,
		Args: cobra.ExactArgs(2),
		RunE: runGrant,
	}
	cmd.Flags().StringSlice("metrics", nil, "For alerts.read: limit the grant to these metric IDs (default: all metrics)")
	return cmd
}

func newRevokePermissionCmd() *cobra.Command {
	return &cobra.Command{
		Use:     "revoke-permission <user-or-name> <permission>",
		Short:   "Take a permission away from a member or admin",
		Long:    `Remove one permission from a member, or metrics.commands.create from an admin (see 'pcmd grant --help' for the keys).`,
		Example: `  pcmd revoke-permission bob invites.manage`,
		Args:    cobra.ExactArgs(2),
		RunE:    runRevokePermission,
	}
}

func permissionTarget(users *pki.UserRegistry, who, key string) (*pki.UserRecord, error) {
	if !authz.KnownPermissions[key] {
		return nil, fmt.Errorf("unknown permission %q; known: %s", key, strings.Join(permissionKeys(), ", "))
	}
	u, err := resolveUser(users, who)
	if err != nil {
		return nil, err
	}
	if u.Owner {
		return nil, fmt.Errorf("%s is the owner and holds every permission already", u.DisplayName)
	}
	if u.Role != pki.RoleMember && !authz.OwnerGrantedPermissions[key] {
		return nil, fmt.Errorf("%s is an admin and holds %s already; admins are granted only %s", u.DisplayName, key, strings.Join(ownerGrantedKeys(), ", "))
	}
	return u, nil
}

func ownerGrantedKeys() []string {
	keys := make([]string, 0, len(authz.OwnerGrantedPermissions))
	for k := range authz.OwnerGrantedPermissions {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

func applyPermissions(audit *slog.Logger, users *pki.UserRegistry, u *pki.UserRecord, perms pki.PermissionSet) error {
	if err := users.SetPermissions(u.UserID, perms); err != nil {
		return err
	}
	granted := make([]string, 0, len(perms))
	for k, g := range perms {
		if g.Granted {
			granted = append(granted, k)
		}
	}
	sort.Strings(granted)
	audit.Info("permission_changed",
		"user_id", u.UserID,
		"granted", granted,
		"changed_by", cliActor,
	)
	return nil
}

func runGrant(cmd *cobra.Command, args []string) error {
	metricIDs, _ := cmd.Flags().GetStringSlice("metrics")
	key := args[1]
	if len(metricIDs) > 0 && key != authz.PermAlertsRead {
		return fmt.Errorf("--metrics only applies to %s", authz.PermAlertsRead)
	}
	db, err := stateDB()
	if err != nil {
		return err
	}
	users := pki.NewUserRegistry(db)
	u, err := permissionTarget(users, args[0], key)
	if err != nil {
		return err
	}
	perms := u.Permissions
	if perms == nil {
		perms = pki.PermissionSet{}
	}
	perms[key] = pki.Grant{Granted: true, Metrics: metricIDs}
	return withAudit(func(audit *slog.Logger) error {
		if err := applyPermissions(audit, users, u, perms); err != nil {
			return err
		}
		if len(metricIDs) > 0 {
			fmt.Fprintf(cmd.OutOrStdout(), "Granted %s to %s for metrics %s.\n", key, u.DisplayName, strings.Join(metricIDs, ", "))
		} else {
			fmt.Fprintf(cmd.OutOrStdout(), "Granted %s to %s.\n", key, u.DisplayName)
		}
		return nil
	})
}

func runRevokePermission(cmd *cobra.Command, args []string) error {
	key := args[1]
	db, err := stateDB()
	if err != nil {
		return err
	}
	users := pki.NewUserRegistry(db)
	u, err := permissionTarget(users, args[0], key)
	if err != nil {
		return err
	}
	if !u.Permissions[key].Granted {
		fmt.Fprintf(cmd.OutOrStdout(), "%s does not hold %s.\n", u.DisplayName, key)
		return nil
	}
	perms := u.Permissions
	delete(perms, key)
	return withAudit(func(audit *slog.Logger) error {
		if err := applyPermissions(audit, users, u, perms); err != nil {
			return err
		}
		fmt.Fprintf(cmd.OutOrStdout(), "Revoked %s from %s.\n", key, u.DisplayName)
		return nil
	})
}

func newRequestsCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "requests",
		Short: "List metric command requests; approve or decline them",
		Long: `List the custom-command metric requests members have filed from the app. A request is a
proposal: nothing runs until it is approved, and approving it makes the server execute
the command on this host on a schedule. In the app, the owner and the admins and members
the owner granted metrics.commands.create approve; this CLI acts as the operator. Every
decision is written to the audit log.`,
		Example: `  pcmd requests
  pcmd requests --json
  pcmd requests approve req-1a2b3c4d5e6f7a8b
  pcmd requests decline req-1a2b3c4d5e6f7a8b`,
		Args: cobra.NoArgs,
		RunE: runRequestsList,
	}
	addJSONFlag(cmd)
	cmd.AddCommand(&cobra.Command{
		Use:     "approve <request-id>",
		Short:   "Approve a pending request: its command starts running on this host",
		Long:    `Approve a pending request. The command is added to the monitoring config and the running service starts collecting it.`,
		Example: `  pcmd requests approve req-1a2b3c4d5e6f7a8b`,
		Args:    cobra.ExactArgs(1),
		RunE: func(c *cobra.Command, args []string) error {
			return decideRequest(c.OutOrStdout(), args[0], "approved")
		},
	})
	cmd.AddCommand(&cobra.Command{
		Use:     "decline <request-id>",
		Short:   "Decline a pending request",
		Long:    `Decline a pending request. The requester sees the decision in the app; nothing runs.`,
		Example: `  pcmd requests decline req-1a2b3c4d5e6f7a8b`,
		Args:    cobra.ExactArgs(1),
		RunE: func(c *cobra.Command, args []string) error {
			return decideRequest(c.OutOrStdout(), args[0], "declined")
		},
	})
	return cmd
}

func runRequestsList(cmd *cobra.Command, args []string) error {
	db, err := stateDB()
	if err != nil {
		return err
	}
	all, err := metrics.NewRequestStore(db).List()
	if err != nil {
		return err
	}
	w := cmd.OutOrStdout()
	if jsonFlag(cmd) {
		if all == nil {
			all = []metrics.MetricRequest{}
		}
		return writeJSON(w, all)
	}
	if len(all) == 0 {
		fmt.Fprintln(w, "No metric command requests.")
		return nil
	}
	users := pki.NewUserRegistry(db)
	fmt.Fprintf(w, "%-20s  %-9s  %-24s  %-14s  %-20s  %s\n", "REQUEST_ID", "STATUS", "LABEL", "REQUESTED_BY", "CREATED", "COMMAND")
	for _, r := range all {
		by := r.RequestedBy
		if u, _ := users.FindByID(r.RequestedBy); u != nil {
			by = u.DisplayName
		}
		fmt.Fprintf(w, "%-20s  %-9s  %-24s  %-14s  %-20s  %s\n",
			r.ID, r.Status, truncate(r.Label, 24), truncate(by, 14), r.CreatedAt, r.Command)
	}
	return nil
}

// Approval writes the command into the monitoring config first so a failed write leaves the request pending.
func decideRequest(w io.Writer, id, status string) error {
	db, err := stateDB()
	if err != nil {
		return err
	}
	requests := metrics.NewRequestStore(db)
	req, err := requests.FindByID(id)
	if err != nil {
		return err
	}
	if req == nil {
		return fmt.Errorf("request %q not found (see `pcmd requests`)", id)
	}
	if req.Status != "pending" {
		return fmt.Errorf("request %s was already %s", req.ID, req.Status)
	}
	return withAudit(func(audit *slog.Logger) error {
		if status == "approved" {
			if err := monitoring.NewStore(db).ApproveCommand(*req); err != nil {
				return fmt.Errorf("add the command to the monitoring config: %w", err)
			}
		}
		decided, err := requests.Decide(id, status, cliActor)
		if err != nil {
			if errors.Is(err, os.ErrNotExist) {
				return fmt.Errorf("request %q not found", id)
			}
			return err
		}
		audit.Info("metric_request_"+status,
			"request_id", decided.ID, "label", decided.Label,
			"requested_by", decided.RequestedBy, "decided_by", cliActor)
		if status == "approved" {
			fmt.Fprintf(w, "Approved %s (%s); the running service picks it up on its next config reload.\n", decided.ID, decided.Label)
		} else {
			fmt.Fprintf(w, "Declined %s (%s).\n", decided.ID, decided.Label)
		}
		return nil
	})
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	if n <= 1 {
		return s[:n]
	}
	return s[:n-1] + "…"
}

func newConfigCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "config",
		Short: "Show the saved server configuration",
		Long: `Read ~/.pocketcmd/config.json. 'config get' prints every saved value. Nothing in it is
settable from the CLI: the values are chosen on the first run, and push notifications
have no server-side switch (every device that opted in within the app is notified).`,
		Example: `  pcmd config get`,
		Args:    cobra.NoArgs,
		RunE:    func(c *cobra.Command, args []string) error { return c.Help() },
	}
	getCmd := &cobra.Command{
		Use:     "get",
		Short:   "Print the saved configuration",
		Long:    `Print the saved configuration: service mode, port, bind address and advertised IP.`,
		Example: `  pcmd config get --json`,
		Args:    cobra.NoArgs,
		RunE:    runConfigGet,
	}
	addJSONFlag(getCmd)
	cmd.AddCommand(getCmd)
	return cmd
}

func loadConfigOrDefault() config.FeatureConfig {
	cfg, err := config.LoadFeatureConfig(config.ConfigFilePath())
	if err != nil {
		return config.DefaultFeatureConfig()
	}
	return cfg
}

func runConfigGet(cmd *cobra.Command, args []string) error {
	cfg := loadConfigOrDefault()
	w := cmd.OutOrStdout()
	if jsonFlag(cmd) {
		return writeJSON(w, cfg)
	}
	fmt.Fprintf(w, "%-16s %s\n", "config_file", config.ConfigFilePath())
	fmt.Fprintf(w, "%-16s %s\n", "service_mode", cfg.ServiceMode)
	fmt.Fprintf(w, "%-16s %s\n", "port", orDefault(fmt.Sprint(cfg.Port), "0", "8767 (default)"))
	fmt.Fprintf(w, "%-16s %s\n", "host", orDefault(cfg.Host, "", defaultBindHost()+" (default: first interface)"))
	fmt.Fprintf(w, "%-16s %s\n", "advertise_ip", orDefault(cfg.AdvertiseIP, "", "(the bind address)"))
	return nil
}

func orDefault(v, empty, shown string) string {
	if v == empty {
		return shown
	}
	return v
}

func newAuditCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "audit",
		Short: "Show the audit log (pairings, invites, role changes, approvals)",
		Long: `Print the newest entries of ~/.pocketcmd/audit.log, oldest first: pairings, invites, role and
permission changes, device removals, metric command approvals and SSH config exports.
--follow keeps printing new entries until Ctrl+C.`,
		Example: `  pcmd audit
  pcmd audit -f
  pcmd audit --since 24h --json`,
		Args: cobra.NoArgs,
		RunE: runAudit,
	}
	addLogFlags(cmd)
	return cmd
}

func runAudit(cmd *cobra.Command, args []string) error {
	opts, err := logOptionsFrom(cmd)
	if err != nil {
		return err
	}
	path := filepath.Join(config.PocketCmdDir(), "audit.log")
	if _, err := os.Stat(path); err != nil {
		fmt.Fprintln(cmd.OutOrStdout(), "No audit log yet.")
		return nil
	}
	return tailFile(cmd.OutOrStdout(), path, opts, interruptChan())
}
