package desec

import (
	"context"
	"golang.org/x/time/rate"
	"time"
)

type rateLimiter interface {
	Wait(context.Context) error
}

var _ rateLimiter = (*rate.Limiter)(nil)

func allowXEveryY(x int64, y time.Duration) rateLimiter {
	return rate.NewLimiter(rate.Every(y/time.Duration(x)), 1)
}

type rateLimiterChain []rateLimiter

var _ rateLimiter = rateLimiterChain(nil)

func (rlc rateLimiterChain) Wait(ctx context.Context) error {
	for _, rl := range rlc {
		if err := rl.Wait(ctx); err != nil {
			return err
		}
	}

	return nil
}
