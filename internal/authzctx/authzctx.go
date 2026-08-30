package authzctx

import "context"

type checkerKey struct{}
type userIDKey struct{}

// WithChecker attaches a fail-closed authorization revalidation callback to
// work derived from an already-authenticated request. The callback must not
// retain raw bearer credentials.
func WithChecker(ctx context.Context, checker func() bool) context.Context {
	return context.WithValue(ctx, checkerKey{}, checker)
}

// Allowed revalidates the caller when a checker is present. Contexts created
// outside the multi-user OAuth path have no checker and retain legacy behavior.
func Allowed(ctx context.Context) bool {
	checker, ok := ctx.Value(checkerKey{}).(func() bool)
	return !ok || (checker != nil && checker())
}

// WithUserID attaches the authenticated immutable account ID after the Relay
// has validated the bearer token. It deliberately carries no credential.
func WithUserID(ctx context.Context, userID string) context.Context {
	return context.WithValue(ctx, userIDKey{}, userID)
}

// UserID returns the authenticated immutable account ID, when the request came
// through an account-aware OAuth resource.
func UserID(ctx context.Context) (string, bool) {
	userID, ok := ctx.Value(userIDKey{}).(string)
	return userID, ok && userID != ""
}
