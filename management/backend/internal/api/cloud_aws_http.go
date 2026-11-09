package api

import (
	"io"
	"net/http"
	"strings"
	"sync/atomic"
	"time"
)

// AW-09: the hand-written AWS clients had no retry/backoff for throttling or
// transient 5xx and no handling of clock skew (a host clock a few minutes off
// makes every signed request fail). awsClient adds bounded retries and learns
// the skew from the server's Date header, which awsSign then applies.

var awsClockSkewNanos atomic.Int64 // server time minus local time

func awsNow() time.Time { return time.Now().Add(time.Duration(awsClockSkewNanos.Load())).UTC() }

type awsRetryTransport struct{ base http.RoundTripper }

func (t awsRetryTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	const maxAttempts = 4
	var resp *http.Response
	var err error
	for attempt := 0; attempt < maxAttempts; attempt++ {
		if attempt > 0 {
			if req.GetBody != nil {
				b, gerr := req.GetBody()
				if gerr != nil {
					return resp, err
				}
				req.Body = b
			} else if req.Body != nil && req.Body != http.NoBody {
				return resp, err // cannot replay a body
			}
			select {
			case <-req.Context().Done():
				return nil, req.Context().Err()
			case <-time.After(time.Duration(1<<uint(attempt-1)) * 500 * time.Millisecond):
			}
		}
		resp, err = t.base.RoundTrip(req)
		if err == nil && resp != nil {
			if d := resp.Header.Get("Date"); d != "" {
				if st, perr := http.ParseTime(d); perr == nil {
					awsClockSkewNanos.Store(int64(time.Until(st)))
				}
			}
		}
		if err != nil {
			continue // network error: retry
		}
		retryable := resp.StatusCode == 429 || resp.StatusCode == 500 || resp.StatusCode == 502 ||
			resp.StatusCode == 503 || resp.StatusCode == 504
		if resp.StatusCode == 400 || resp.StatusCode == 403 {
			// Throttling is sometimes reported as 400 ThrottlingException.
			peek, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
			resp.Body.Close()
			resp.Body = io.NopCloser(strings.NewReader(string(peek)))
			s := string(peek)
			retryable = strings.Contains(s, "Throttling") || strings.Contains(s, "RequestLimitExceeded") ||
				strings.Contains(s, "SlowDown") || strings.Contains(s, "RequestTimeTooSkewed")
		}
		if !retryable || attempt == maxAttempts-1 {
			return resp, nil
		}
		io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
	}
	return resp, err
}

var awsClient = &http.Client{
	Transport: awsRetryTransport{base: newGuardedTransport()},
	Timeout:   2 * time.Minute,
}
