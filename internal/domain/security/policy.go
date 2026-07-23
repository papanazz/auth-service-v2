package security

import "time"

type LimitPolicy struct {
	Limit int

	Window time.Duration
}
