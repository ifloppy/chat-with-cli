package authzctx

import "context"

type checkerKey struct{}

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
