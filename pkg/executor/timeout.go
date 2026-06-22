package executor

import (
	"context"
	"time"
)

func withTimeout(ctx context.Context, timeoutSeconds int64) (context.Context, context.CancelFunc) {
	if timeoutSeconds <= 0 {
		timeoutSeconds = 300
	}
	return context.WithTimeout(ctx, time.Duration(timeoutSeconds)*time.Second)
}
