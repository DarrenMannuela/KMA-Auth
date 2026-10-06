package handler

import (
	"testing"
	"time"
)

func TestUntilText(t *testing.T) {
	for d, want := range map[time.Duration]string{
		20 * time.Second:             "in about a minute",
		5 * time.Minute:              "in about 5 minutes",
		89 * time.Minute:             "in about 89 minutes",
		2*time.Hour + 40*time.Minute: "in about 3 hours",
		6 * time.Hour:                "in about 6 hours",
	} {
		if got := untilText(d); got != want {
			t.Errorf("untilText(%v) = %q, want %q", d, got, want)
		}
	}
}
