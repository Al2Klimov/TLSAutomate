package desec

import (
	"bytes"
	log "github.com/sirupsen/logrus"
	"io"
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

type splitter struct {
	io.ReadCloser

	copy io.Writer
}

var _ io.ReadCloser = (*splitter)(nil)

func (s *splitter) Read(p []byte) (n int, err error) {
	if n, err = s.ReadCloser.Read(p); n > 0 {
		if _, errWr := s.copy.Write(p[:n]); errWr != nil && err == nil {
			err = errWr
		}
	}

	return
}

type logMiddleware struct {
	logger *log.Entry
	next   http.RoundTripper
}

var _ http.RoundTripper = (*logMiddleware)(nil)

func (lm *logMiddleware) RoundTrip(req *http.Request) (*http.Response, error) {
	body := &bytes.Buffer{}
	if req.Body != nil {
		withSplitter := &http.Request{}
		*withSplitter = *req
		withSplitter.Body = &splitter{req.Body, body}
		req = withSplitter
	}

	resp, err := lm.next.RoundTrip(req)
	logger := lm.logger.WithFields(log.Fields{"method": req.Method, "url": req.URL.String()})

	if err == nil {
		logger = logger.WithField("status", resp.StatusCode)
		if resp.StatusCode >= 400 && resp.StatusCode <= 499 {
			logger = logger.WithField("body", body.String())
		}
	} else {
		logger = logger.WithError(err)
	}

	logger.Debug("performed HTTP request")
	return resp, err
}
