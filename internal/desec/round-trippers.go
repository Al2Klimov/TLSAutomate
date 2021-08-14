package desec

import (
	log "github.com/sirupsen/logrus"
	"net/http"
)

type rateLimitedHttp struct {
	rl   rateLimiter
	next http.RoundTripper
}

var _ http.RoundTripper = (*rateLimitedHttp)(nil)

func (rlh *rateLimitedHttp) RoundTrip(request *http.Request) (*http.Response, error) {
	if err := rlh.rl.Wait(request.Context()); err != nil {
		return nil, err
	}

	return rlh.next.RoundTrip(request)
}

type logMiddleware struct {
	logger *log.Entry
	next   http.RoundTripper
}

var _ http.RoundTripper = (*logMiddleware)(nil)

func (lm *logMiddleware) RoundTrip(req *http.Request) (*http.Response, error) {
	resp, err := lm.next.RoundTrip(req)
	logger := lm.logger.WithFields(log.Fields{"method": req.Method, "url": req.URL.String()})

	if err == nil {
		logger = logger.WithField("status", resp.StatusCode)
	} else {
		logger = logger.WithError(err)
	}

	logger.Debug("performed HTTP request")
	return resp, err
}
