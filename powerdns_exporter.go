package main

import (
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	_ "net/http/pprof"
	"net/url"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	hashiver "github.com/hashicorp/go-version"

	"github.com/alecthomas/kingpin/v2"

	"github.com/go-kit/log"
	"github.com/go-kit/log/level"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/prometheus/common/promlog"
	"github.com/prometheus/common/promlog/flag"
	"github.com/prometheus/common/version"
)

const (
	namespace        = "powerdns"
	apiInfoEndpoint  = "servers/localhost"
	apiStatsEndpoint = "servers/localhost/statistics"
)

var (
	client = &http.Client{
		Transport: &http.Transport{
			Dial: func(netw, addr string) (net.Conn, error) {
				c, err := net.DialTimeout(netw, addr, 5*time.Second)
				if err != nil {
					return nil, err
				}
				if err := c.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
					return nil, err
				}
				return c, nil
			},
		},
	}
)

// ServerInfo is used to parse JSON data from 'server/localhost' endpoint
type ServerInfo struct {
	Kind       string `json:"type"`
	ID         string `json:"id"`
	URL        string `json:"url"`
	DaemonType string `json:"daemon_type"`
	Version    string `json:"version"`
	ConfigURL  string `json:"config_url"`
	ZonesURL   string `json:"zones_url"`
}

// StatsEntry contains the Item property which contains the actual item
type StatsEntry struct {
	Item interface{}
}

// StatisticItemEntry holds values of ring and map statistic items
type StatisticItemEntry struct {
	Name  string  `json:"name"`
	Value float64 `json:"value,string"`
}

// StatisticItem contains just one value
type StatisticItem struct {
	Name  string  `json:"name"`
	Kind  string  `json:"type"`
	Value float64 `json:"value,string"`
}

// StatisticCollectionItem holds ring and map statistic items
type StatisticCollectionItem struct {
	Name  string               `json:"name"`
	Kind  string               `json:"type"`
	Value []StatisticItemEntry `json:"value,string"`
}

// UnmarshalJSON dynamically parses statistic items based on their type
func (d *StatsEntry) UnmarshalJSON(data []byte) error {
	var typ struct {
		Kind string `json:"type"`
	}

	if err := json.Unmarshal(data, &typ); err != nil {
		return err
	}

	switch typ.Kind {
	case "StatisticItem":
		d.Item = new(StatisticItem)
	case "RingStatisticItem":
		fallthrough
	case "MapStatisticItem":
		d.Item = new(StatisticCollectionItem)
	default:
		return errors.New("unsupported Statistic Type")
	}

	return json.Unmarshal(data, d.Item)
}

// Exporter collects PowerDNS stats from the given HostURL and exports them using
// the prometheus metrics package.
type Exporter struct {
	HostURL    *url.URL
	ServerType string
	APIKey     string
	mutex      sync.RWMutex
	logger     log.Logger

	up                prometheus.Gauge
	totalScrapes      prometheus.Counter
	jsonParseFailures prometheus.Counter

	gaugeDefs    []gaugeDefinition
	gaugeMetrics map[int]prometheus.Gauge

	counterDefs          []counterDefinition
	counterMetrics       map[int]*prometheus.Desc
	simpleCounterMetrics map[int]*prometheus.Desc
	simpleCounterDefs    []simpleCounterDefinition
}

func newGaugeMetric(serverType, metricName, docString string) prometheus.Gauge {
	return prometheus.NewGauge(
		prometheus.GaugeOpts{
			Namespace: namespace,
			Subsystem: serverType,
			Name:      metricName,
			Help:      docString,
		},
	)
}

// NewExporter returns an initialized Exporter.
func NewExporter(apiKey, serverType string, serverVersion *hashiver.Version, hostURL *url.URL, logger log.Logger) *Exporter {
	var gaugeDefs []gaugeDefinition
	var counterDefs []counterDefinition
	var simpleCounterDefs []simpleCounterDefinition

	gaugeMetrics := make(map[int]prometheus.Gauge)
	counterMetrics := make(map[int]*prometheus.Desc)
	simpleCounterMetrics := make(map[int]*prometheus.Desc)

	simpleCounterDefs = []simpleCounterDefinition{}
	switch serverType {
	case "recursor":
		gaugeDefs = recursorGaugeDefs
		counterDefs = recursorCounterDefs
	case "authoritative":
		gaugeDefs = authoritativeGaugeDefs
		counterDefs = authoritativeCounterDefs
		var v42, _ = hashiver.NewVersion("4.2.0")
		if serverVersion.GreaterThanOrEqual(v42) {
			simpleCounterDefs = authoritativeSimpleCounterDefs
		}
	case "dnsdist":
		gaugeDefs = dnsdistGaugeDefs
		counterDefs = dnsdistCounterDefs
	}

	for _, def := range gaugeDefs {
		gaugeMetrics[def.id] = newGaugeMetric(serverType, def.name, def.desc)
	}

	for _, def := range counterDefs {
		counterMetrics[def.id] = prometheus.NewDesc(
			prometheus.BuildFQName(
				namespace,
				serverType,
				def.name,
			),
			def.desc,
			[]string{def.label},
			nil,
		)
	}

	for _, def := range simpleCounterDefs {
		simpleCounterMetrics[def.id] = prometheus.NewDesc(
			prometheus.BuildFQName(
				namespace,
				serverType,
				def.name,
			),
			def.desc,
			[]string{def.labelName},
			nil,
		)
	}

	return &Exporter{
		HostURL:    hostURL,
		ServerType: serverType,
		APIKey:     apiKey,
		logger:     logger,
		up: prometheus.NewGauge(prometheus.GaugeOpts{
			Namespace: namespace,
			Subsystem: serverType,
			Name:      "up",
			Help:      "Was the last scrape of PowerDNS successful.",
		}),
		totalScrapes: prometheus.NewCounter(prometheus.CounterOpts{
			Namespace: namespace,
			Subsystem: serverType,
			Name:      "exporter_total_scrapes",
			Help:      "Current total PowerDNS scrapes.",
		}),
		jsonParseFailures: prometheus.NewCounter(prometheus.CounterOpts{
			Namespace: namespace,
			Subsystem: serverType,
			Name:      "exporter_json_parse_failures",
			Help:      "Number of errors while parsing PowerDNS JSON stats.",
		}),
		gaugeMetrics:         gaugeMetrics,
		counterMetrics:       counterMetrics,
		simpleCounterMetrics: simpleCounterMetrics,
		gaugeDefs:            gaugeDefs,
		counterDefs:          counterDefs,
		simpleCounterDefs:    simpleCounterDefs,
	}
}

// Describe describes all the metrics ever exported by the PowerDNS exporter. It
// implements prometheus.Collector.
func (e *Exporter) Describe(ch chan<- *prometheus.Desc) {
	for _, m := range e.counterMetrics {
		ch <- m
	}
	for _, m := range e.simpleCounterMetrics {
		ch <- m
	}
	for _, m := range e.gaugeMetrics {
		ch <- m.Desc()
	}
	ch <- e.up.Desc()
	ch <- e.totalScrapes.Desc()
	ch <- e.jsonParseFailures.Desc()
}

// Collect fetches the stats from configured PowerDNS API URI and delivers them
// as Prometheus metrics. It implements prometheus.Collector.
func (e *Exporter) Collect(ch chan<- prometheus.Metric) {
	e.mutex.Lock()
	defer e.mutex.Unlock()

	stats := e.scrape()
	ch <- e.up
	ch <- e.totalScrapes
	ch <- e.jsonParseFailures

	e.collectMetrics(ch, stats)
}

func (e *Exporter) scrape() []StatsEntry {
	e.totalScrapes.Inc()

	var data []StatsEntry
	url := apiURL(e.HostURL, apiStatsEndpoint)
	err := getJSON(url, e.APIKey, &data)
	if err != nil {
		e.up.Set(0)
		e.jsonParseFailures.Inc()
		level.Error(e.logger).Log("msg", "Error scraping PowerDNS", "err", err)
		return nil
	}

	e.up.Set(1)
	return data
}

func (e *Exporter) collectMetrics(ch chan<- prometheus.Metric, stats []StatsEntry) {
	statsMap := make(map[string]float64)
	statsCollectionMap := make(map[string][]StatisticItemEntry)
	for _, s := range stats {
		switch item := s.Item.(type) {
		case *StatisticItem:
			statsMap[item.Name] = item.Value
		case *StatisticCollectionItem:
			statsCollectionMap[item.Name] = item.Value
		}
	}
	if len(statsMap) > 0 {
		e.processStatsMap(ch, statsMap)
	}
	if len(statsCollectionMap) > 0 {
		e.processStatsCollectionMap(ch, statsCollectionMap)
	}
	if e.ServerType == "recursor" {
		h, err := makeRecursorRTimeHistogram(statsMap)
		if err != nil {
			level.Error(e.logger).Log("msg", "Could not create response time histogram", "err", err)
			return
		}
		ch <- h
	}
}

func (e *Exporter) processStatsMap(ch chan<- prometheus.Metric, statsMap map[string]float64) {
	for _, def := range e.gaugeDefs {
		if value, ok := statsMap[def.key]; ok {
			// latency gauges need to be converted from microseconds to seconds
			if strings.HasSuffix(def.key, "latency") {
				value = value / 1000000
			}
			e.gaugeMetrics[def.id].Set(value)
			ch <- e.gaugeMetrics[def.id]
		} else {
			level.Error(e.logger).Log("msg", "Expected PowerDNS stats key not found", "key", def.key)
			e.jsonParseFailures.Inc()
		}
	}

	for _, def := range e.counterDefs {
		for key, label := range def.labelMap {
			if value, ok := statsMap[key]; ok {
				ch <- prometheus.MustNewConstMetric(e.counterMetrics[def.id], prometheus.CounterValue, float64(value), label)
			} else {
				level.Error(e.logger).Log("msg", "Expected PowerDNS stats key not found", "key", key)
				e.jsonParseFailures.Inc()
			}
		}
	}
}

func (e *Exporter) processStatsCollectionMap(ch chan<- prometheus.Metric, statsCollectionMap map[string][]StatisticItemEntry) {

	for _, def := range e.simpleCounterDefs {
		if items, ok := statsCollectionMap[def.key]; ok {
			for _, item := range items {
				ch <- prometheus.MustNewConstMetric(e.simpleCounterMetrics[def.id], prometheus.CounterValue, item.Value, item.Name)
			}
		} else {
			level.Error(e.logger).Log("msg", "Expected PowerDNS stats key not found", "key", def.key)
			e.jsonParseFailures.Inc()
		}
	}
}

func getServerInfo(hostURL *url.URL, apiKey string) (*ServerInfo, error) {
	var info ServerInfo
	url := apiURL(hostURL, apiInfoEndpoint)
	err := getJSON(url, apiKey, &info)
	if err != nil {
		return nil, err
	}

	return &info, nil
}

func getJSON(url, apiKey string, data interface{}) error {
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return err
	}

	req.Header.Add("X-API-Key", apiKey)
	resp, err := client.Do(req)
	if err != nil {
		return err
	}

	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		content, err := io.ReadAll(resp.Body)
		if err != nil {
			return err
		}
		return errors.New(string(content))
	}

	if err := json.NewDecoder(resp.Body).Decode(data); err != nil {
		return err
	}

	return nil
}

func apiURL(hostURL *url.URL, path string) string {
	endpointURI, _ := url.Parse(path)
	u := hostURL.ResolveReference(endpointURI)
	return u.String()
}

func main() {
	var (
		listenAddress = kingpin.Flag("listen-address", "Address to listen on for web interface and telemetry.").Default(":9120").String()
		metricsPath   = kingpin.Flag("metric-path", "Path under which to expose metrics.").Default("/metrics").String()
		apiURL        = kingpin.Flag("api-url", "Base-URL of PowerDNS authoritative server/recursor API.").Default("http://localhost:8081/api/v1/").String()
		apiKey        = kingpin.Flag("api-key", "PowerDNS API Key").Default("").String()
	)
	promlogConfig := &promlog.Config{}
	flag.AddFlags(kingpin.CommandLine, promlogConfig)
	kingpin.Version(version.Print("powerdns_exporter"))
	kingpin.HelpFlag.Short('h')
	kingpin.Parse()
	logger := promlog.New(promlogConfig)

	hostURL, err := url.Parse(*apiURL)
	if err != nil {
		level.Error(logger).Log("msg", "Error parsing api-url", "err", err)
	}

	server, err := getServerInfo(hostURL, *apiKey)
	if err != nil {
		level.Error(logger).Log("msg", "Could not fetch PowerDNS server info", "err", err)
	}

	pdnsver, err := hashiver.NewVersion(server.Version)
	if err != nil {
		level.Error(logger).Log("msg", "Could not parse PowerDNS server version", "err", err)
	}

	exporter := NewExporter(*apiKey, server.DaemonType, pdnsver, hostURL, logger)
	prometheus.MustRegister(exporter)

	level.Info(logger).Log("msg", "Starting Server", "ip", *listenAddress)

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)

	http.Handle(*metricsPath, promhttp.Handler())
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`<html>
             <head><title>PowerDNS Exporter</title></head>
             <body>
             <h1>PowerDNS Exporter</h1>
             <p><a href='` + *metricsPath + `'>Metrics</a></p>
             </body>
             </html>`))
	})

	go func() {
		level.Error(logger).Log("msg", "Error starting", "err", http.ListenAndServe(*listenAddress, nil))
	}()

	<-stop
}
