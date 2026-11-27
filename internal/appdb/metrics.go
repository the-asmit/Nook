package appdb

import (
	"context"
	"fmt"
	"time"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/the-asmit/nook/internal/store"
)

// metrics are the app database metrics: events seen by this instance, and
// the server's state read from the database when scraped.
type metrics struct {
	failover *prometheus.HistogramVec
	backups  *prometheus.CounterVec
	created  prometheus.Counter
}

func newMetrics(reg prometheus.Registerer, st *store.Store) (*metrics, error) {
	m := &metrics{
		failover: prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Name:    "nook_appdb_failover_seconds",
			Help:    "Time from the cause of a new server generation (node death, planned stop, failed start) to the new server accepting connections.",
			Buckets: []float64{5, 10, 20, 30, 60, 120, 300, 600, 1800, 3600},
		}, []string{"cause"}),
		backups: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "nook_appdb_backups_total", Help: "Base backups of the app database server, by result.",
		}, []string{"result"}),
		created: prometheus.NewCounter(prometheus.CounterOpts{Name: "nook_appdb_databases_created_total", Help: "App databases created."}),
	}
	for _, c := range []prometheus.Collector{m.failover, m.backups, m.created, &serverState{store: st}} {
		if err := reg.Register(c); err != nil {
			return nil, fmt.Errorf("register app database metrics: %w", err)
		}
	}
	return m, nil
}

// serverState reports the current server's state from the database, so
// every control-plane instance shows the same values.
type serverState struct{ store *store.Store }

var (
	upDesc         = prometheus.NewDesc("nook_appdb_server_up", "1 when the app database server accepts connections.", nil, nil)
	generationDesc = prometheus.NewDesc("nook_appdb_server_generation", "Generation of the current app database server (each failover adds one).", nil, nil)
	databasesDesc  = prometheus.NewDesc("nook_appdb_databases", "App databases.", nil, nil)
	sizeDesc       = prometheus.NewDesc("nook_appdb_size_bytes", "Total size of the app databases.", nil, nil)
	connsDesc      = prometheus.NewDesc("nook_appdb_connections", "Client connections to the app database server.", nil, nil)
	failuresDesc   = prometheus.NewDesc("nook_appdb_archive_failures", "Failed WAL archive attempts of the current server (pg_stat_archiver.failed_count).", nil, nil)
	archiveAgeDesc = prometheus.NewDesc("nook_appdb_last_archive_age_seconds", "Seconds since the last WAL segment was archived.", nil, nil)
	backupAgeDesc  = prometheus.NewDesc("nook_appdb_last_backup_age_seconds", "Seconds since the last base backup finished.", nil, nil)
)

// Describe implements prometheus.Collector.
func (s *serverState) Describe(ch chan<- *prometheus.Desc) {
	for _, d := range []*prometheus.Desc{upDesc, generationDesc, databasesDesc, sizeDesc, connsDesc, failuresDesc, archiveAgeDesc, backupAgeDesc} {
		ch <- d
	}
}

// Collect implements prometheus.Collector.
func (s *serverState) Collect(ch chan<- prometheus.Metric) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	gauge := func(d *prometheus.Desc, v float64) { ch <- prometheus.MustNewConstMetric(d, prometheus.GaugeValue, v) }
	if n, err := s.store.CountAppDatabases(ctx); err == nil {
		gauge(databasesDesc, float64(n))
	}
	srv, err := s.store.CurrentDBServer(ctx)
	if err != nil {
		if store.IsNotFound(err) {
			gauge(upDesc, 0)
		}
		return
	}
	up := 0.0
	if srv.State == store.AppDbServerStateRunning {
		up = 1
	}
	gauge(upDesc, up)
	gauge(generationDesc, float64(srv.Generation))
	gauge(sizeDesc, float64(srv.DatabasesSizeBytes))
	gauge(connsDesc, float64(srv.Connections))
	gauge(failuresDesc, float64(srv.ArchiveFailedCount))
	now := time.Now()
	if srv.LastArchivedAt != nil {
		gauge(archiveAgeDesc, now.Sub(*srv.LastArchivedAt).Seconds())
	}
	if srv.LastBackupAt != nil {
		gauge(backupAgeDesc, now.Sub(*srv.LastBackupAt).Seconds())
	}
}
