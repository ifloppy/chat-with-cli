package oauthserver

import (
	"fmt"
	"net"
	"net/http"
	"strings"
	"time"
)

type rateWindow struct {
	Started time.Time
	Count   int
}

func parseTrustedProxyCIDRs(values []string) ([]*net.IPNet, error) {
	proxies := make([]*net.IPNet, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		if !strings.Contains(value, "/") {
			ip := net.ParseIP(value)
			if ip == nil {
				return nil, fmt.Errorf("invalid trusted proxy address %q", value)
			}
			bits := 128
			if ip.To4() != nil {
				ip = ip.To4()
				bits = 32
			}
			value = fmt.Sprintf("%s/%d", ip.String(), bits)
		}
		_, network, err := net.ParseCIDR(value)
		if err != nil {
			return nil, fmt.Errorf("invalid trusted proxy CIDR %q: %w", value, err)
		}
		proxies = append(proxies, network)
	}
	return proxies, nil
}

func ipTrusted(ip net.IP, trusted []*net.IPNet) bool {
	if ip == nil {
		return false
	}
	for _, network := range trusted {
		if network.Contains(ip) {
			return true
		}
	}
	return false
}

func requestIP(r *http.Request, trusted []*net.IPNet) string {
	remote := ""
	if host, _, err := net.SplitHostPort(strings.TrimSpace(r.RemoteAddr)); err == nil {
		remote = host
	} else {
		remote = strings.TrimSpace(r.RemoteAddr)
	}
	remoteIP := net.ParseIP(remote)
	if remoteIP == nil {
		return "unknown"
	}
	if !ipTrusted(remoteIP, trusted) {
		return remoteIP.String()
	}

	// X-Forwarded-For is an append-style chain. Walk from the proxy nearest
	// to us toward the client and discard only addresses in explicitly trusted
	// proxy ranges. Taking the left-most value would let a client prepend a
	// spoofed address and evade per-IP limits.
	forwarded := strings.Split(r.Header.Get("X-Forwarded-For"), ",")
	for i := len(forwarded) - 1; i >= 0; i-- {
		ip := net.ParseIP(strings.TrimSpace(forwarded[i]))
		if ip == nil {
			continue
		}
		if !ipTrusted(ip, trusted) {
			return ip.String()
		}
	}
	if realIP := net.ParseIP(strings.TrimSpace(r.Header.Get("X-Real-IP"))); realIP != nil && !ipTrusted(realIP, trusted) {
		return realIP.String()
	}
	return remoteIP.String()
}

func (s *Server) allowRate(r *http.Request, bucket string, limit int, window time.Duration) bool {
	if limit <= 0 {
		return true
	}
	key := bucket + "|" + requestIP(r, s.trustedProxies)
	now := time.Now()
	s.rateMu.Lock()
	defer s.rateMu.Unlock()
	if len(s.rates) >= maxRateEntries {
		for key, entry := range s.rates {
			if now.Sub(entry.Started) >= time.Hour {
				delete(s.rates, key)
			}
		}
		if len(s.rates) >= maxRateEntries {
			return false
		}
	}
	entry := s.rates[key]
	if entry.Started.IsZero() || now.Sub(entry.Started) >= window {
		entry = rateWindow{Started: now}
	}
	if entry.Count >= limit {
		s.rates[key] = entry
		return false
	}
	entry.Count++
	s.rates[key] = entry
	return true
}

func rateLimited(w http.ResponseWriter, retryAfter int) {
	w.Header().Set("Retry-After", fmt.Sprint(retryAfter))
	http.Error(w, "rate limit exceeded; retry later", http.StatusTooManyRequests)
}
