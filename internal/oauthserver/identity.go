package oauthserver

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"strings"
	"time"

	"golang.org/x/crypto/argon2"
)

const (
	ModePrivate = "private"
	ModePublic  = "public"

	maxUsers        = 4096
	sessionLifetime = 30 * 24 * time.Hour
	sessionCookie   = "cwc_session"

	argonTime    uint32 = 2
	argonMemory  uint32 = 19 * 1024
	argonThreads uint8  = 1
	argonKeyLen  uint32 = 32
)

var dummyPasswordHash = func() string {
	salt := []byte("chat-with-cli-dummy")
	key := argon2.IDKey([]byte("dummy-password-for-timing-only"), salt, argonTime, argonMemory, argonThreads, argonKeyLen)
	return fmt.Sprintf("argon2id$v=19$m=%d,t=%d,p=%d$%s$%s", argonMemory, argonTime, argonThreads,
		base64.RawStdEncoding.EncodeToString(salt), base64.RawStdEncoding.EncodeToString(key))
}()

var usernamePattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]{2,63}$`)

type User struct {
	ID           string `json:"id"`
	Username     string `json:"username"`
	PasswordHash string `json:"password_hash"`
	CreatedAt    int64  `json:"created_at"`
	LastLoginAt  int64  `json:"last_login_at,omitempty"`
	Admin        bool   `json:"admin,omitempty"`
	Disabled     bool   `json:"disabled,omitempty"`
}

type sessionRecord struct {
	UserID       string `json:"user_id"`
	CreatedAt    int64  `json:"created_at"`
	LastSeenAt   int64  `json:"last_seen_at"`
	LastReauthAt int64  `json:"last_reauth_at,omitempty"`
	Expires      int64  `json:"expires"`
}

func normalizeMode(mode string) (string, error) {
	mode = strings.ToLower(strings.TrimSpace(mode))
	if mode == "" {
		return ModePrivate, nil
	}
	if mode != ModePrivate && mode != ModePublic {
		return "", fmt.Errorf("instance mode must be private or public, got %q", mode)
	}
	return mode, nil
}

func normalizeUsername(username string) (string, bool) {
	username = strings.TrimSpace(username)
	if !usernamePattern.MatchString(username) {
		return "", false
	}
	return strings.ToLower(username), true
}

func validatePassword(password string) error {
	if len(password) < 12 {
		return errors.New("password must be at least 12 characters")
	}
	if len(password) > 1024 {
		return errors.New("password is too long")
	}
	return nil
}

func hashPassword(password string) (string, error) {
	if err := validatePassword(password); err != nil {
		return "", err
	}
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}
	key := argon2.IDKey([]byte(password), salt, argonTime, argonMemory, argonThreads, argonKeyLen)
	return fmt.Sprintf("argon2id$v=19$m=%d,t=%d,p=%d$%s$%s", argonMemory, argonTime, argonThreads,
		base64.RawStdEncoding.EncodeToString(salt), base64.RawStdEncoding.EncodeToString(key)), nil
}

func verifyPassword(encoded, password string) bool {
	parts := strings.Split(encoded, "$")
	if len(parts) != 5 || parts[0] != "argon2id" || parts[1] != "v=19" {
		return false
	}
	var memory, iterations uint32
	var threads uint8
	if _, err := fmt.Sscanf(parts[2], "m=%d,t=%d,p=%d", &memory, &iterations, &threads); err != nil {
		return false
	}
	if memory == 0 || memory > 64*1024 || iterations == 0 || iterations > 10 || threads == 0 || threads > 8 {
		return false
	}
	salt, err := base64.RawStdEncoding.DecodeString(parts[3])
	if err != nil || len(salt) < 8 || len(salt) > 64 {
		return false
	}
	want, err := base64.RawStdEncoding.DecodeString(parts[4])
	if err != nil || len(want) < 16 || len(want) > 64 {
		return false
	}
	got := argon2.IDKey([]byte(password), salt, iterations, memory, threads, uint32(len(want)))
	return subtle.ConstantTimeCompare(got, want) == 1
}

func (s *Server) createUserLocked(username, password string, admin ...bool) (User, error) {
	normalized, ok := normalizeUsername(username)
	if !ok {
		return User{}, errors.New("username must be 3-64 letters, digits, dot, underscore, or hyphen")
	}
	if _, exists := s.usernames[normalized]; exists {
		return User{}, errors.New("username is already registered")
	}
	if len(s.users) >= maxUsers {
		return User{}, errors.New("user limit reached")
	}
	hash, err := hashPassword(password)
	if err != nil {
		return User{}, err
	}
	isAdmin := len(admin) > 0 && admin[0]
	user := User{ID: randomToken(18), Username: strings.TrimSpace(username), PasswordHash: hash, CreatedAt: time.Now().Unix(), Admin: isAdmin}
	s.users[user.ID] = user
	s.usernames[normalized] = user.ID
	return user, nil
}

func (s *Server) authenticate(username, password string) (User, bool, bool) {
	normalized, ok := normalizeUsername(username)
	if len(password) > 1024 {
		return User{}, false, false
	}
	s.mu.Lock()
	user := User{}
	if ok {
		user = s.users[s.usernames[normalized]]
	}
	s.mu.Unlock()
	select {
	case s.passwordSlots <- struct{}{}:
		defer func() { <-s.passwordSlots }()
	case <-time.After(2 * time.Second):
		return User{}, false, true
	}
	if user.ID == "" || user.Disabled {
		_ = verifyPassword(dummyPasswordHash, password)
		return User{}, false, false
	}
	ok = verifyPassword(user.PasswordHash, password)
	if !ok {
		return User{}, false, false
	}
	s.mu.Lock()
	current, exists := s.users[user.ID]
	if !exists || current.ID == "" || current.Disabled || current.PasswordHash != user.PasswordHash {
		s.mu.Unlock()
		return User{}, false, false
	}
	current.LastLoginAt = time.Now().Unix()
	s.users[user.ID] = current
	s.mu.Unlock()
	return current, true, false
}

func (s *Server) register(username, password string) (User, error, bool) {
	normalized, ok := normalizeUsername(username)
	if !ok {
		return User{}, errors.New("username must be 3-64 letters, digits, dot, underscore, or hyphen"), false
	}
	if err := validatePassword(password); err != nil {
		return User{}, err, false
	}
	select {
	case s.passwordSlots <- struct{}{}:
		defer func() { <-s.passwordSlots }()
	case <-time.After(2 * time.Second):
		return User{}, errors.New("registration capacity is busy; retry shortly"), true
	}
	hash, err := hashPassword(password)
	if err != nil {
		return User{}, err, false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, exists := s.usernames[normalized]; exists {
		return User{}, errors.New("username is already registered"), false
	}
	if len(s.users) >= maxUsers {
		return User{}, errors.New("user limit reached"), false
	}
	user := User{ID: randomToken(18), Username: strings.TrimSpace(username), PasswordHash: hash, CreatedAt: time.Now().Unix()}
	s.users[user.ID] = user
	s.usernames[normalized] = user.ID
	if err := s.saveLocked(); err != nil {
		delete(s.users, user.ID)
		delete(s.usernames, normalized)
		return User{}, err, false
	}
	return user, nil, false
}

func (s *Server) clearSession(w http.ResponseWriter, r *http.Request) {
	if cookie, err := r.Cookie(sessionCookie); err == nil && cookie.Value != "" {
		s.mu.Lock()
		delete(s.sessions, tokenKey(cookie.Value))
		_ = s.saveLocked()
		s.mu.Unlock()
	}
	http.SetCookie(w, &http.Cookie{
		Name: sessionCookie, Value: "", Path: "/", MaxAge: -1,
		HttpOnly: true, Secure: s.base.Scheme == "https", SameSite: http.SameSiteLaxMode,
	})
}

func (s *Server) sessionUser(r *http.Request) (User, bool) {
	cookie, err := r.Cookie(sessionCookie)
	if err != nil || cookie.Value == "" {
		return User{}, false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.cleanupLocked(time.Now())
	record, ok := s.sessions[tokenKey(cookie.Value)]
	if !ok {
		return User{}, false
	}
	user, ok := s.users[record.UserID]
	if !ok || user.Disabled {
		return User{}, false
	}
	now := time.Now()
	if record.LastSeenAt == 0 || now.Sub(time.Unix(record.LastSeenAt, 0)) >= 5*time.Minute {
		record.LastSeenAt = now.Unix()
		s.sessions[tokenKey(cookie.Value)] = record
		_ = s.saveLocked()
	}
	return user, true
}

func (s *Server) createSession(authenticated User) (string, error) {
	token := randomToken(32)
	s.mu.Lock()
	current, exists := s.users[authenticated.ID]
	if !exists || current.ID == "" || current.Disabled {
		s.mu.Unlock()
		return "", errors.New("authenticated user is disabled or no longer exists")
	}
	if authenticated.PasswordHash == "" || current.PasswordHash != authenticated.PasswordHash {
		s.mu.Unlock()
		return "", errors.New("authenticated credentials changed before session creation")
	}
	now := time.Now().Unix()
	snapshot := s.snapshotMutableStateLocked()
	s.sessions[tokenKey(token)] = sessionRecord{UserID: current.ID, CreatedAt: now, LastSeenAt: now, LastReauthAt: now, Expires: time.Now().Add(sessionLifetime).Unix()}
	if s.persistenceFault {
		// Recovery sessions are process-local. Browser login must remain
		// possible without consuming a dirty authorization-state guard.
		s.mu.Unlock()
		return token, nil
	}
	err := s.saveOrRollbackLocked(snapshot)
	s.mu.Unlock()
	if err != nil {
		return "", err
	}
	return token, nil
}

func (s *Server) setSessionCookie(w http.ResponseWriter, token string) {
	http.SetCookie(w, &http.Cookie{
		Name: sessionCookie, Value: token, Path: "/", MaxAge: int(sessionLifetime.Seconds()),
		HttpOnly: true, Secure: s.base.Scheme == "https", SameSite: http.SameSiteLaxMode,
	})
}

func (s *Server) UserCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.users)
}

func (s *Server) DeviceOwner(device string) (User, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	user, ok := s.users[s.devices[device]]
	return user, ok
}
