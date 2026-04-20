package handlers

import "context"

type contextKey string

const userContextKey contextKey = "auth_user"

type ContextUser struct {
	ID    int64
	Email string
}

func WithUser(ctx context.Context, user ContextUser) context.Context {
	return context.WithValue(ctx, userContextKey, user)
}

func UserFromContext(ctx context.Context) (ContextUser, bool) {
	user, ok := ctx.Value(userContextKey).(ContextUser)
	return user, ok
}
