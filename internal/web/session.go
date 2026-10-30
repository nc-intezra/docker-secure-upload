package web

import "context"

type sidKey struct{}

// The raw session ID stays inside this package; other packages only ever
// see its hash (reqctx.Info.SessionHash).
func withSID(ctx context.Context, sid string) context.Context {
	return context.WithValue(ctx, sidKey{}, sid)
}

func sidFrom(ctx context.Context) (string, bool) {
	v, ok := ctx.Value(sidKey{}).(string)
	return v, ok && v != ""
}
