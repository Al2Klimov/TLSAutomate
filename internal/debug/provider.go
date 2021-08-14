package debug

import (
	. "TLSAutomate/internal"
	"context"
	"github.com/Al2Klimov/FUeL.go"
)

type Debug struct{}

var _ Output = Debug{}

func (Debug) Kind() string {
	return "debug"
}

func (Debug) Number() int {
	return 1
}

func (Debug) Ping(context.Context) fuel.ErrorWithStack {
	return nil
}

func (d Debug) Update(_ context.Context, del, create OutputRecordSet) fuel.ErrorWithStack {
	logger := ProviderLog(d)

	logger.WithField("records", del).Debug("would delete records")
	logger.WithField("records", create).Debug("would create records")

	return nil
}
