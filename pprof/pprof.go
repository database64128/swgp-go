package pprof

import (
	"context"
	"net"
	"net/http"
	_ "net/http/pprof"

	"go.uber.org/zap"
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
func (c Config) NewService(logger *zap.Logger) *Service {
	network := c.ListenNetwork
	if network == "" {
		network = "tcp"
	}

	errorLog, err := zap.NewStdLogAt(logger, zap.ErrorLevel)
	if err != nil {
		// For now, panic instead of returning an error.
		// Once we migrate to log/slog, there won't be any error to handle.
		panic(err)
	}

	return &Service{
		logger:  logger,
		network: network,
		server: http.Server{
			Addr:     c.ListenAddress,
			Handler:  logPprofRequests(logger, http.DefaultServeMux),
			ErrorLog: errorLog,
		},
	}
}

// logPprofRequests is a middleware that logs pprof requests.
func logPprofRequests(logger *zap.Logger, h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h.ServeHTTP(w, r)
		logger.Info("Handled pprof request",
			zap.String("proto", r.Proto),
			zap.String("method", r.Method),
			zap.String("requestURI", r.RequestURI),
			zap.String("host", r.Host),
			zap.String("remoteAddr", r.RemoteAddr),
		)
	})
}

// Service implements [service.Service].
type Service struct {
	logger  *zap.Logger
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
			s.logger.Error("Failed to serve pprof", zap.Error(err))
		}
	}()

	s.logger.Info("Started pprof", zap.Stringer("listenAddress", ln.Addr()))
	return nil
}

// Stop implements [service.Service.Stop].
func (s *Service) Stop() error {
	return s.server.Close()
}
