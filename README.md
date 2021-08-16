# TLSAutomate

Manages TLSA DNS records automatically based on X.509 certificates.

## Usage

```bash
docker run --rm -d \
  -v tlsautomate:/data \
  -v traefik1_acme:/acme1 \
  -v traefik2_acme:/acme2 \
  -e TLSAUTOMATE_CONFIG='
inputs:
  # https://traefik.io
  traefik:  # supports multiple ones
  - acme_json: /acme1/acme.json  # the containing directory should be mounted,
  - acme_json: /acme2/acme.json  # not just the file
ports:  # default: all
  tcp:
  - 25
  - 443
  udp:
  - 42
records:  # sane defaults (may change!)
  ttl: 3600
  cert_usage: 3
  selector: 1
  match_type: 1
outputs:
  debug: true
  # https://desec.io
  desec:  # supports multiple ones
  - token: ABCDEFGHIabcdefghi12345678-_  # only outputs records
  - token: JKLMNOPQRSTUVjklmnopqrstuv90  # for already present domains
' \
  grandmaster/tlsautomate
```

## Caveats

* Before adding an output, purge the `tlsautomate:/data` volume!
* After removing an output, clean the TLSA records by yourself.
* Wildcard certificate SANs (like `*.example.com`) are **not** translated
  to TLSA records `_25._tcp.*.example.com.` and `_443._tcp.*.example.com.`
  (even if only the ports 25 and 443 are configured),
  but to `*.example.com.` (effectively all ports).
* If the input only provides `*.example.com`, but the output detects
  an A/AAAA record for e.g. `smtp.example.com.`,
  TLSA records for `smtp.example.com.` are implied.
* The above feature doesn't work post-factum.
  I.e.: on A/AAAA record creation copy the `*.example.com.` TLSA record
  to `*._tcp.smtp.example.com.` by yourself.
