package oauthserver

import (
	"net/http"
	"strings"
)

func (s *Server) handleInstallScript(w http.ResponseWriter, r *http.Request) {
	github := strings.TrimRight(s.cfg.GitHubURL, "/")
	if github == "" {
		github = "https://github.com/ifloppy/chat-with-cli"
	}
	w.Header().Set("Cache-Control", "no-store")
	http.Redirect(w, r, github+"/raw/refs/heads/main/install.sh", http.StatusTemporaryRedirect)
}
