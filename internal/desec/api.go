package desec

import (
	. "TLSAutomate/internal"
	"bytes"
	"context"
	"encoding/json"
	"github.com/Al2Klimov/FUeL.go"
	"github.com/hashicorp/go-cleanhttp"
	"github.com/hashicorp/go-retryablehttp"
	"github.com/tomnomnom/linkheader"
	"io"
	"net/http"
	"net/url"
	"reflect"
	"time"
)

func (d *DeSEC) paginate(ctx context.Context, uri *url.URL, resp interface{}) fuel.ErrorWithStack {
	q := uri.RawQuery
	if q != "" {
		q += "&"
	}

	q += "cursor="
	uri = uri.ResolveReference(&url.URL{RawQuery: q})
	vResp := reflect.ValueOf(resp)

Pages:
	for {
		vPage := reflect.New(vResp.Type().Elem())

		header, err := d.rest(ctx, d.apiRead(), "GET", uri, nil, vPage.Interface())
		if err != nil {
			return err
		}

		if vPageElem := vPage.Elem(); vPageElem.Len() > 0 {
			if vRespElem := vResp.Elem(); vRespElem.Len() == 0 {
				vRespElem.Set(vPageElem)
			} else {
				vRespElem = reflect.AppendSlice(vRespElem, vPageElem)
			}
		}

		for _, links := range header.Values("Link") {
			for _, link := range linkheader.Parse(links) {
				if link.Rel == "next" {
					next, err := url.Parse(link.URL)
					if err != nil {
						return fuel.AttachStackToError(err, 0)
					}

					uri = uri.ResolveReference(next)
					continue Pages
				}
			}
		}

		return nil
	}
}

func (d *DeSEC) rest(
	ctx context.Context, client *http.Client, method string, uri *url.URL, body, resp interface{},
) (http.Header, fuel.ErrorWithStack) {
	req := (&http.Request{
		Method: method,
		URL:    uri,
		Header: http.Header{"Authorization": []string{"Token " + d.Token}},
	}).WithContext(ctx)
	if body != nil {
		buf := &bytes.Buffer{}
		enc := json.NewEncoder(buf)
		enc.SetEscapeHTML(false)

		if err := enc.Encode(body); err != nil {
			return nil, fuel.AttachStackToError(err, 0)
		}

		req.Body = io.NopCloser(buf)
		req.Header.Set("Content-Type", "application/json")
	}

	response, err := client.Do(req)
	if err != nil {
		return nil, fuel.AttachStackToError(err, 0)
	}
	defer func() { _ = response.Body.Close() }()

	if response.StatusCode > 299 {
		return nil, fuel.AttachStackToError(httpStatus(response.StatusCode), 0)
	}

	if resp != nil {
		if err := json.NewDecoder(response.Body).Decode(resp); err != nil {
			return nil, fuel.AttachStackToError(err, 0)
		}
	}

	return response.Header, nil
}

func (d *DeSEC) apiRead() *http.Client {
	d.once.Do(d.init)
	return d.read
}

func (d *DeSEC) apiWriteRrsets() *http.Client {
	d.once.Do(d.init)
	return d.writeRrsets
}

func (d *DeSEC) init() {
	const day = 24 * time.Hour
	a := allowXEveryY
	user := a(2000, day) // https://desec.readthedocs.io/en/latest/rate-limits.html
	tx := &logMiddleware{ProviderLog(d), cleanhttp.DefaultPooledTransport()}

	r := retryablehttp.NewClient()
	r.Logger = nil
	r.HTTPClient = &http.Client{
		Transport: &rateLimitedHttp{rateLimiterChain{user, a(10, time.Second), a(50, time.Minute)}, tx},
	}
	d.read = r.StandardClient()

	wr := retryablehttp.NewClient()
	wr.Logger = nil
	wr.HTTPClient = &http.Client{Transport: &rateLimitedHttp{
		rateLimiterChain{user, a(2, time.Second), a(15, time.Minute), a(30, time.Hour), a(300, day)},
		tx,
	}}
	d.writeRrsets = wr.StandardClient()
}
