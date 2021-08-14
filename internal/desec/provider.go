package desec

import (
	. "TLSAutomate/internal"
	"context"
	"encoding/hex"
	"fmt"
	"github.com/Al2Klimov/FUeL.go"
	"net/http"
	"net/url"
	"strings"
	"sync"
)

type DeSEC struct {
	Numbered

	Token       string
	once        sync.Once
	read        *http.Client
	writeRrsets *http.Client
}

var _ Output = (*DeSEC)(nil)

func (*DeSEC) Kind() string {
	return "deSEC"
}

func (d *DeSEC) Ping(ctx context.Context) fuel.ErrorWithStack {
	_, err := d.rest(ctx, d.apiRead(), "GET", v1Domains, nil, new([]struct{}))
	return err
}

func (d *DeSEC) Update(ctx context.Context, del, create OutputRecordSet) fuel.ErrorWithStack {
	var domains []struct {
		Name string `json:"name"`
	}
	if err := d.paginate(ctx, v1Domains, &domains); err != nil {
		return err
	}

	domainSuffixes := map[string]string{}
	for _, domain := range domains {
		domainSuffixes[domain.Name] = "." + domain.Name
	}

	recordDomains := map[OutputRecord][2]string{}
	relevantDomains := map[string]struct{}{}

	for _, ors := range [2]OutputRecordSet{del, create} {
		for or := range ors {
			for domain, suffix := range domainSuffixes {
				if strings.HasSuffix(or.Service, suffix) {
					recordDomains[or] = [2]string{domain, strings.TrimSuffix(or.Service, suffix)}
					relevantDomains[domain] = struct{}{}
					break
				}
			}
		}
	}

	subNames := map[string]map[string]struct{}{}
	rm := map[string]map[string]struct{}{}
	patch := map[string]map[string]map[string]interface{}{}
	add := map[string]map[string]map[string]interface{}{}

	for domain := range relevantDomains {
		subNames[domain] = map[string]struct{}{}
		rm[domain] = map[string]struct{}{}
		patch[domain] = map[string]map[string]interface{}{}
		add[domain] = map[string]map[string]interface{}{}
	}

	for domain, perDomain := range subNames {
		var records []struct {
			SubName string `json:"subname"`
		}

		err := d.paginate(
			ctx,
			v1Domains.ResolveReference(&url.URL{Path: url.PathEscape(domain) + "/rrsets/", RawQuery: "type=TLSA"}),
			&records,
		)
		if err != nil {
			return err
		}

		for _, record := range records {
			perDomain[record.SubName] = struct{}{}
		}
	}

	for or := range del {
		if dm, ok := recordDomains[or]; ok {
			if _, ok := subNames[dm[0]][dm[1]]; ok {
				rm[dm[0]][dm[1]] = struct{}{}
			}
		}
	}

	for or := range create {
		if dm, ok := recordDomains[or]; ok {
			add[dm[0]][dm[1]] = map[string]interface{}{
				"subname": dm[1],
				"type":    "TLSA",
				"records": [1]string{fmt.Sprintf(
					"%d %d %d %s",
					or.CertUsage, or.Selector, or.MatchType, strings.ToUpper(hex.EncodeToString([]byte(or.CertSpec))),
				)},
				"ttl": or.Ttl,
			}
		}
	}

	for domain, add := range add {
		patch := patch[domain]
		rm := rm[domain]

		for sub, rrSet := range add {
			if _, ok := rm[sub]; ok {
				patch[sub] = rrSet
			}
		}
	}

	for domain, patch := range patch {
		rm := rm[domain]
		add := add[domain]

		for sub := range patch {
			delete(rm, sub)
			delete(add, sub)
		}
	}

	for domain, perDomain := range subNames {
		patch := patch[domain]
		add := add[domain]

		for sub := range perDomain {
			if rrSet, ok := add[sub]; ok {
				patch[sub] = rrSet
				delete(add, sub)
			}
		}
	}

	for domain, subs := range patch {
		var body []map[string]interface{}
		for _, rrSet := range subs {
			body = append(body, rrSet)
		}

		if len(body) < 1 {
			continue
		}

		_, err := d.rest(
			ctx, d.apiWriteRrsets(), "PUT",
			v1Domains.ResolveReference(&url.URL{Path: url.PathEscape(domain) + "/rrsets/"}), body, nil,
		)
		if err != nil {
			return err
		}
	}

	for domain, subs := range add {
		var body []map[string]interface{}
		for _, rrSet := range subs {
			body = append(body, rrSet)
		}

		if len(body) < 1 {
			continue
		}

		_, err := d.rest(
			ctx, d.apiWriteRrsets(), "POST",
			v1Domains.ResolveReference(&url.URL{Path: url.PathEscape(domain) + "/rrsets/"}), body, nil,
		)
		if err != nil {
			return err
		}
	}

	for domain, subs := range rm {
		var body []map[string]interface{}
		for sub := range subs {
			body = append(body, map[string]interface{}{"subname": sub, "type": "TLSA", "records": [0]string{}})
		}

		if len(body) < 1 {
			continue
		}

		_, err := d.rest(
			ctx, d.apiWriteRrsets(), "PATCH",
			v1Domains.ResolveReference(&url.URL{Path: url.PathEscape(domain) + "/rrsets/"}), body, nil,
		)
		if err != nil {
			return err
		}
	}

	return nil
}
