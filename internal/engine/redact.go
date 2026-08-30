package engine

import (
	"errors"
	"strings"
)

const (
	maxRedactLineTerms = 64
	maxRedactTermBytes = 128
)

func NormalizeRedactLineTerms(values []string) ([]string, error) {
	if len(values) > maxRedactLineTerms {
		return nil, errors.New("too many redact-line terms")
	}
	seen := make(map[string]struct{}, len(values))
	out := make([]string, 0, len(values))
	for _, value := range values {
		term := strings.ToLower(strings.TrimSpace(value))
		if term == "" {
			continue
		}
		if len(term) > maxRedactTermBytes || strings.ContainsAny(term, "\r\n") {
			return nil, errors.New("redact-line term must be a single line of at most 128 bytes")
		}
		if _, ok := seen[term]; ok {
			continue
		}
		seen[term] = struct{}{}
		out = append(out, term)
	}
	return out, nil
}

func (e *Engine) redactText(text string) string {
	if text == "" || len(e.cfg.RedactLineTerms) == 0 {
		return text
	}
	parts := strings.SplitAfter(text, "\n")
	for i, part := range parts {
		body, ending := part, ""
		if strings.HasSuffix(body, "\n") {
			body = strings.TrimSuffix(body, "\n")
			ending = "\n"
			if strings.HasSuffix(body, "\r") {
				body = strings.TrimSuffix(body, "\r")
				ending = "\r\n"
			}
		}
		lower := strings.ToLower(body)
		for _, term := range e.cfg.RedactLineTerms {
			if strings.Contains(lower, term) {
				parts[i] = "[REDACTED LINE]" + ending
				break
			}
		}
	}
	return strings.Join(parts, "")
}
func (e *Engine) redactTaskInfo(info TaskInfo) TaskInfo {
	info.Name = e.redactText(info.Name)
	info.Command = e.redactText(info.Command)
	return info
}
