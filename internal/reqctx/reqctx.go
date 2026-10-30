// Package reqctx carries per-request identity set by the web middleware.
package reqctx

import "context"

type key struct{}

// Info identifies the browser session and client behind a request.
type Info struct {
	SessionHash string // hex SHA-256 of the session cookie value
	ClientIP    string
}

// With returns ctx carrying info.
func With(ctx context.Context, info Info) context.Context {
	return context.WithValue(ctx, key{}, info)
}

// From returns the info stored by With, if any.
func From(ctx context.Context) (Info, bool) {
	v, ok := ctx.Value(key{}).(Info)
	return v, ok && v.SessionHash != ""
}
