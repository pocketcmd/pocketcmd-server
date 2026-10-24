package server

import (
	"net/http"

	"github.com/pocketcmd/pocketcmd-server/internal/httperr"
	"github.com/pocketcmd/pocketcmd-server/internal/pki"
)

func (s *Server) handleHostKeys(w http.ResponseWriter, r *http.Request) {
	httperr.WriteJSON(w, http.StatusOK, map[string]interface{}{
		"fingerprints": pki.MachineSSHHostKeyFingerprints(),
	})
}
