# PowerDNS Exporter

[![Travis](https://img.shields.io/travis/janeczku/powerdns_exporter.svg)](https://travis-ci.org/janeczku/powerdns_exporter)

[PowerDNS](https://www.powerdns.com/) exporter for [Prometheus](http://prometheus.io/)

Periodically scrapes metrics via the [PowerDNS HTTP-API](https://doc.powerdns.com/md/httpapi/README/) and exports them via HTTP/JSON for consumption by Prometheus.

---

## Flags

Name | Description | Default
---- | ---- | ----
listen-address | Host:Port pair to run exporter on | `:9120`
metric-path | Path under which to expose metrics for Prometheus | `/metrics`
api-url | Base-URL of PowerDNS authoritative server/recursor API | `http://localhost:8081/api/v1/`
api-key | PowerDNS API Key | `-`

The `api-url` flag value should be passed in this format:

* PowerDNS server/recursor 3.x: `http://<HOST>:<API-PORT>/`
* PowerDNS server/recursor 4.x: `http://<HOST>:<API-PORT>/api/v1/`

## Building

It is automated with goreleaser.

## Usage

[See here](https://doc.powerdns.com/md/httpapi/README/) for instructions on how to enable the HTTP API in PowerDNS.

Then run the exporter like this:

```bash
powerdns_exporter -api-url="http://<HOST>:<API-PORT>/api/v1/" -api-key="<YOUR_API_KEY>"
```

Show help:

```bash
powerdns_exporter --help
```
