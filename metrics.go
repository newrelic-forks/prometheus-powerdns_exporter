package main

import (
	"fmt"
	"sort"

	"github.com/prometheus/client_golang/prometheus"
)

// Used to programmatically create prometheus.Gauge metrics
type gaugeDefinition struct {
	id   int
	name string
	desc string
	key  string
}

// Used to programmatically create prometheus.Counter metrics
type counterDefinition struct {
	id    int
	name  string
	desc  string
	label string
	// Maps PowerDNS stats names to Prometheus label value
	labelMap map[string]string
}

// Used to programmatically create prometheus.Counter metrics
// for PowerDNS metrics in ring or map format
type simpleCounterDefinition struct {
	id        int
	name      string
	desc      string
	labelName string
	key       string
}

var (
	rTimeBucketMap = map[string]float64{
		"answers0-1":      .001,
		"answers1-10":     .01,
		"answers10-100":   .1,
		"answers100-1000": 1,
		"answers-slow":    0,
	}

	rTimeLabelMap = map[string]string{
		"answers0-1":      "0_1ms",
		"answers1-10":     "1_10ms",
		"answers10-100":   "10_100ms",
		"answers100-1000": "100_1000ms",
		"answers-slow":    "over_1000ms",
	}

	rCodeLabelMap = map[string]string{
		"servfail-answers": "servfail",
		"nxdomain-answers": "nxdomain",
		"noerror-answers":  "noerror",
	}

	exceptionsLabelMap = map[string]string{
		"resource-limits":     "resource_limit",
		"over-capacity-drops": "over_capacity_drop",
		"unreachables":        "ns_unreachable",
		"outgoing-timeouts":   "outgoing_timeout",
	}
)

// PowerDNS recursor metrics definitions
var (
	recursorGaugeDefs = []gaugeDefinition{
		{1, "latency_average_seconds", "Exponential moving average of question-to-answer latency.", "qa-latency"},
		{2, "concurrent_queries", "Number of concurrent queries.", "concurrent-queries"},
		{3, "cache_size", "Number of entries in the cache.", "cache-entries"},
	}

	recursorCounterDefs = []counterDefinition{
		{
			1, "incoming_queries_total", "Total number of incoming queries by network.", "net",
			map[string]string{"questions": "udp", "tcp-questions": "tcp"},
		},
		{
			2, "outgoing_queries_total", "Total number of outgoing queries by network.", "net",
			map[string]string{"all-outqueries": "udp", "tcp-outqueries": "tcp"},
		},
		{
			3, "cache_lookups_total", "Total number of cache lookups by result.", "result",
			map[string]string{"cache-hits": "hit", "cache-misses": "miss"},
		},
		{4, "answers_rcodes_total", "Total number of answers by response code.", "rcode", rCodeLabelMap},
		{5, "answers_rtime_total", "Total number of answers grouped by response time slots.", "timeslot", rTimeLabelMap},
		{6, "exceptions_total", "Total number of exceptions by error.", "error", exceptionsLabelMap},
	}
)

// PowerDNS authoritative server metrics definitions
var (
	authoritativeGaugeDefs = []gaugeDefinition{
		{1, "security_status", "PDNS Server Security status based on security-status.secpoll.powerdns.com", "security-status"},
		{2, "latency_average_seconds", "Average number of microseconds a packet spends within PowerDNS", "latency"},
		{3, "packet_cache_size", "Number of entries in the packet cache.", "packetcache-size"},
		{4, "signature_cache_size", "Number of entries in the signature cache.", "signature-cache-size"},
		{5, "key_cache_size", "Number of entries in the key cache.", "key-cache-size"},
		{6, "metadata_cache_size", "Number of entries in the metadata cache.", "meta-cache-size"},
		{7, "qsize", "Number of packets waiting for database attention.", "qsize-q"},
	}
	authoritativeCounterDefs = []counterDefinition{
		{
			1, "incoming_notifications", "Number of NOTIFY packets that were received", "type",
			map[string]string{},
		},
		{
			2, "uptime", "Uptime in seconds of the daemon", "type",
			map[string]string{"uptime": "seconds"},
		},
		{
			3, "dnssec", "DNSSEC counters", "type",
			map[string]string{"signatures": "signatures_created", "udp-do-queries": "ok_queries_recv"},
		},
		{
			4, "packet_cache_lookup", "Packet cache lookups by result", "result",
			map[string]string{"packetcache-hit": "hit", "packetcache-miss": "miss"},
		},
		{
			5, "query_cache_lookup", "Query cache lookups by result", "result",
			map[string]string{"query-cache-hit": "hit", "query-cache-miss": "miss"},
		},
		{
			6, "deferred_cache_actions", "Deferred cache actions because of maintenance by type", "type",
			map[string]string{"deferred-cache-inserts": "inserts", "deferred-cache-lookup": "lookups"},
		},
		{
			7, "dnsupdate_queries_total", "Total number of DNS update queries by status.", "status",
			map[string]string{"dnsupdate-answers": "answered", "dnsupdate-changes": "applied", "dnsupdate-queries": "requested", "dnsupdate-refused": "refused"},
		},
		{
			8, "recursive_queries_total", "Total number of recursive queries by status.", "status",
			map[string]string{"rd-queries": "requested", "recursing-questions": "processed", "recursing-answers": "answered", "recursion-unanswered": "unanswered"},
		},
		{
			9, "queries_total", "Total number of queries by protocol.", "proto",
			map[string]string{"tcp-queries": "tcp",
				"tcp4-queries": "tcp4",
				"tcp6-queries": "tcp6",
				"udp-queries":  "udp",
				"udp4-queries": "udp4",
				"udp6-queries": "udp6"},
		},
		{
			10, "answers_total", "Total number of answers by protocol.", "proto",
			map[string]string{"tcp-answers": "tcp",
				"tcp4-answers": "tcp4",
				"tcp6-answers": "tcp6",
				"udp-answers":  "udp",
				"udp4-answers": "udp4",
				"udp6-answers": "udp6"},
		},
		{
			11, "answers_bytes_total", "Total number of answer bytes sent over by protocol.", "proto",
			map[string]string{"tcp-answers-bytes": "tcp",
				"tcp4-answers-bytes": "tcp4",
				"tcp6-answers-bytes": "tcp6",
				"udp-answers-bytes":  "udp",
				"udp4-answers-bytes": "udp4",
				"udp6-answers-bytes": "udp6"},
		},
		{
			12, "exceptions_total", "Total number of exceptions by error.", "error",
			map[string]string{"servfail-packets": "servfail",
				"timedout-packets":   "timeout",
				"corrupt-packets":    "corrupt_packets",
				"overload-drops":     "backend_overload",
				"udp-recvbuf-errors": "recvbuf_errors",
				"udp-sndbuf-errors":  "sndbuf_errors",
				"udp-in-errors":      "udp_in_errors",
				"udp-noport-errors":  "udp_noport_errors"},
		},
		{
			13, "cpu_utilisation", "Number of CPU milliseconds spent in user, and kernel space", "type",
			map[string]string{"sys-msec": "sys", "user-msec": "user"},
		},
	}

	authoritativeSimpleCounterDefs = []simpleCounterDefinition{
		{
			1, "response_sizes", "Size distribution of responses", "size", "response-sizes",
		},
		{
			2, "response_rcodes", "Distribution of rcodes", "rcode", "response-by-rcode",
		},
		{
			3, "remote_queries", "Remote server IP addresses", "remote", "remotes",
		},
		{
			4, "remote_queries_unauth", "Remote hosts querying domains for which we are not auth", "remote", "remotes-unauth",
		},
		{
			5, "remote_queries_corrupt", "Remote hosts sending corrupt packets", "remote", "remotes-corrupt",
		},
		{
			6, "queries", "UDP Queries Received", "record", "queries",
		},
		{
			7, "queries_noerror", "Queries for existing records, but for type we don't have", "record", "noerror-queries",
		},
		{
			8, "queries_unauth", "Queries for domains that we are not authoritative for", "record", "unauth-queries",
		},
		{
			9, "queries_nxdomain", "Queries for non-existent records within existent domains", "record", "nxdomain-queries",
		},
		{
			10, "queries_servfail", "Queries that could not be answered due to backend errors", "record", "servfail-queries",
		},
	}
)

// PowerDNS Dnsdist metrics definitions
var (
	dnsdistGaugeDefs   = []gaugeDefinition{}
	dnsdistCounterDefs = []counterDefinition{}
)

// Creates a fixed-value response time histogram from the following stats counters:
// answers0-1, answers1-10, answers10-100, answers100-1000, answers-slow
func makeRecursorRTimeHistogram(statsMap map[string]float64) (prometheus.Metric, error) {
	buckets := make(map[float64]uint64)
	var count uint64
	for k, v := range rTimeBucketMap {
		if _, ok := statsMap[k]; !ok {
			return nil, fmt.Errorf("required PowerDNS stats key not found: %s", k)
		}
		value := statsMap[k]
		if v != 0 {
			buckets[v] = uint64(value)
		}
		count += uint64(value)
	}

	// Convert linear buckets to cumulative buckets
	var keys []float64
	for k := range buckets {
		keys = append(keys, k)
	}
	sort.Float64s(keys)
	var cumsum uint64
	for _, k := range keys {
		cumsum = cumsum + buckets[k]
		buckets[k] = cumsum
	}

	desc := prometheus.NewDesc(
		namespace+"_recursor_response_time_seconds",
		"Histogram of PowerDNS recursor response times in seconds.",
		[]string{},
		prometheus.Labels{},
	)

	h := prometheus.MustNewConstHistogram(desc, count, 0, buckets)
	return h, nil
}
