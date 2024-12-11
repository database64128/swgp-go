package pprof

import (
	"context"
	"log/slog"
	"net"
	"net/http"
	_ "net/http/pprof"

	"github.com/database64128/swgp-go/tslog"
)

// Config is the configuration for the pprof service.
type Config struct {
	// Enabled controls whether the pprof service is enabled.
	Enabled bool `json:"enabled"`

	// ListenNetwork is the network to listen on.
	ListenNetwork string `json:"listenNetwork"`

	// ListenAddress is the address to listen on.
	ListenAddress string `json:"listenAddress"`
}

// NewService creates a new pprof service.
func (c Config) NewService(logger *tslog.Logger) *Service {
	network := c.ListenNetwork
	if network == "" {
		network = "tcp"
	}

	return &Service{
		logger:  logger,
		network: network,
		server: http.Server{
			Addr:     c.ListenAddress,
			Handler:  logPprofRequests(logger, http.DefaultServeMux),
			ErrorLog: slog.NewLogLogger(logger.Handler(), slog.LevelError),
		},
	}
}

// logPprofRequests is a middleware that logs pprof requests.
func logPprofRequests(logger *tslog.Logger, h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h.ServeHTTP(w, r)
		logger.Info("Handled pprof request",
			slog.String("proto", r.Proto),
			slog.String("method", r.Method),
			slog.String("requestURI", r.RequestURI),
			slog.String("host", r.Host),
			slog.String("remoteAddr", r.RemoteAddr),
		)
	})
}

// Service implements [service.Service].
type Service struct {
	logger  *tslog.Logger
	network string
	server  http.Server
}

// String implements [service.Service.String].
func (*Service) String() string {
	return "pprof"
}

// Start implements [service.Service.Start].
func (s *Service) Start(ctx context.Context) error {
	var lc net.ListenConfig
	ln, err := lc.Listen(ctx, s.network, s.server.Addr)
	if err != nil {
		return err
	}

	go func() {
		if err := s.server.Serve(ln); err != nil && err != http.ErrServerClosed {
			s.logger.Error("Failed to serve pprof", tslog.Err(err))
		}
	}()

	s.logger.Info("Started pprof", slog.Any("listenAddress", ln.Addr()))
	return nil
}

// Stop implements [service.Service.Stop].
func (s *Service) Stop() error {
	return s.server.Close()
}
