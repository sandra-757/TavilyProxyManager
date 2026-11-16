package jobs

import (
	"context"
	"log/slog"
	"time"

	"tavily-proxy/server/internal/services"
)

func StartMonthlyReset(ctx context.Context, keys *services.KeyService, logger *slog.Logger) {
	go func() {
		for {
			// Tavily's billing month is anchored to UTC; resetting on a
			// local timezone could clear the local ledger up to a day
			// before/after the upstream quota actually refreshes.
			now := time.Now().UTC()
			nextMidnight := time.Date(now.Year(), now.Month(), now.Day()+1, 0, 0, 0, 0, time.UTC)
			timer := time.NewTimer(time.Until(nextMidnight))
			select {
			case <-ctx.Done():
				timer.Stop()
				return
			case <-timer.C:
				if nextMidnight.Day() == 1 {
					if err := keys.ResetAllUsage(context.Background()); err != nil {
						logger.Error("monthly reset failed", "err", err)
					} else {
						logger.Info("monthly quota reset completed")
					}
				}
			}
		}
	}()
}

