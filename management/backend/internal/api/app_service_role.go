package api

// app_service_role.go - what a discovered (Tier 0) service most likely is, so
// lists can put the services that matter first: instrumented services, then
// well-known platform software (databases, caches, web servers, runtimes),
// then likely in-house applications, then everything else.

import (
	"encoding/json"
	"path/filepath"
	"sort"
	"strings"
)

type appRole struct {
	Role  string // database | cache | web | runtime | queue | search | app | other
	Label string // e.g. "PostgreSQL"
	Rank  int    // lower sorts first within Tier 0
}

// appKnownPlatforms maps a process or service name (lower case, version
// suffixes removed) to what it is. Ranks: data stores first (they hold the
// data), then what faces the network, then runtimes and brokers.
var appKnownPlatforms = map[string]appRole{
	"postgres": {"database", "PostgreSQL", 1}, "postmaster": {"database", "PostgreSQL", 1}, "postgresql": {"database", "PostgreSQL", 1},
	"mysqld": {"database", "MySQL", 1}, "mysql": {"database", "MySQL", 1}, "mariadbd": {"database", "MariaDB", 1}, "mariadb": {"database", "MariaDB", 1},
	"mongod": {"database", "MongoDB", 1}, "mongodb": {"database", "MongoDB", 1}, "sqlservr": {"database", "SQL Server", 1},
	"oracle": {"database", "Oracle", 1}, "tnslsnr": {"database", "Oracle listener", 1}, "cockroach": {"database", "CockroachDB", 1},
	"clickhouse-server": {"database", "ClickHouse", 1}, "clickhouse": {"database", "ClickHouse", 1}, "influxd": {"database", "InfluxDB", 1},
	"cassandra": {"database", "Cassandra", 1}, "couchdb": {"database", "CouchDB", 1}, "neo4j": {"database", "Neo4j", 1},
	"redis-server": {"cache", "Redis", 2}, "redis": {"cache", "Redis", 2}, "valkey-server": {"cache", "Valkey", 2}, "keydb-server": {"cache", "KeyDB", 2},
	"memcached": {"cache", "Memcached", 2},
	"nginx":     {"web", "nginx", 3}, "apache2": {"web", "Apache httpd", 3}, "httpd": {"web", "Apache httpd", 3}, "caddy": {"web", "Caddy", 3},
	"haproxy": {"web", "HAProxy", 3}, "envoy": {"web", "Envoy", 3}, "traefik": {"web", "Traefik", 3}, "lighttpd": {"web", "lighttpd", 3},
	"openresty": {"web", "OpenResty", 3}, "squid": {"web", "Squid", 3}, "varnishd": {"web", "Varnish", 3}, "iis": {"web", "IIS", 3}, "w3wp": {"web", "IIS", 3},
	"php-fpm": {"runtime", "PHP-FPM", 4}, "php": {"runtime", "PHP", 4}, "tomcat": {"runtime", "Tomcat", 4}, "catalina": {"runtime", "Tomcat", 4},
	"jboss": {"runtime", "JBoss", 4}, "wildfly": {"runtime", "WildFly", 4}, "jetty": {"runtime", "Jetty", 4}, "uwsgi": {"runtime", "uWSGI", 4},
	"gunicorn": {"runtime", "Gunicorn", 4}, "unicorn": {"runtime", "Unicorn", 4}, "puma": {"runtime", "Puma", 4}, "passenger": {"runtime", "Passenger", 4},
	"keycloak": {"runtime", "Keycloak", 4}, "vault": {"runtime", "Vault", 4}, "gitea": {"runtime", "Gitea", 4}, "jenkins": {"runtime", "Jenkins", 4},
	"grafana": {"runtime", "Grafana", 5}, "grafana-server": {"runtime", "Grafana", 5}, "minio": {"database", "MinIO", 1},
	"rabbitmq-server": {"queue", "RabbitMQ", 5}, "beam.smp": {"queue", "RabbitMQ", 5}, "rabbitmq": {"queue", "RabbitMQ", 5},
	"kafka": {"queue", "Kafka", 5}, "zookeeper": {"queue", "ZooKeeper", 5}, "nats-server": {"queue", "NATS", 5}, "mosquitto": {"queue", "Mosquitto", 5},
	"elasticsearch": {"search", "Elasticsearch", 5}, "opensearch": {"search", "OpenSearch", 5}, "solr": {"search", "Solr", 5}, "etcd": {"database", "etcd", 2},
}

// appNameVariants returns lookup keys for a name: as is, without a version or
// digit suffix ("php-fpm8.2", "postgres-16"), and the base of a path.
func appNameVariants(n string) []string {
	n = strings.ToLower(strings.TrimSpace(filepath.Base(n)))
	if n == "" || n == "." || n == "/" {
		return nil
	}
	out := []string{n}
	t := strings.TrimRight(n, "0123456789.")
	t = strings.TrimRight(t, "-_")
	if t != n && t != "" {
		out = append(out, t)
	}
	if i := strings.IndexAny(n, ":@"); i > 0 {
		out = append(out, n[:i])
	}
	return out
}

// appServiceRole classifies a service from its name, then from the image and
// executable of its instances (attrs). Instrumented services are applications.
func appServiceRole(name string, attrs json.RawMessage, images []string, tier int) appRole {
	cands := []string{name}
	var a struct {
		Exe   string `json:"exe"`
		Image string `json:"image"`
	}
	_ = json.Unmarshal(attrs, &a)
	cands = append(cands, a.Exe, a.Image)
	for _, im := range images {
		// "docker.io/library/postgres:16" -> "postgres"
		if i := strings.LastIndex(im, "/"); i >= 0 {
			im = im[i+1:]
		}
		cands = append(cands, im)
	}
	for _, c := range cands {
		for _, v := range appNameVariants(c) {
			if r, ok := appKnownPlatforms[v]; ok {
				return r
			}
		}
	}
	if tier >= 1 {
		return appRole{"app", "", 0}
	}
	// A Tier 0 service with a language runtime is most likely an in-house
	// application (java -jar orders.jar, node checkout.js, gunicorn orders.wsgi).
	var l struct {
		Language string `json:"language"`
	}
	_ = json.Unmarshal(attrs, &l)
	if l.Language != "" {
		return appRole{"app", "", 6}
	}
	return appRole{"other", "", 9}
}

// appSortServices orders a list: Tier 2, Tier 1, then Tier 0 by role rank;
// within a group, services with traffic or more instances first, then name.
func appSortServices(list []appServiceRow) {
	sort.SliceStable(list, func(i, j int) bool {
		a, b := list[i], list[j]
		if a.Tier != b.Tier {
			return a.Tier > b.Tier
		}
		if a.Tier == 0 && a.RoleRank != b.RoleRank {
			return a.RoleRank < b.RoleRank
		}
		ca, cb := int64(0), int64(0)
		if a.Red != nil {
			ca = a.Red.Calls
		}
		if b.Red != nil {
			cb = b.Red.Calls
		}
		if ca != cb {
			return ca > cb
		}
		if a.Instances != b.Instances {
			return a.Instances > b.Instances
		}
		return a.Name < b.Name
	})
}
