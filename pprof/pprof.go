package pprof

import (
	"context"
	"net"
	"net/http"
	_ "net/http/pprof"

	"go.uber.org/zap"
)

// PprofConfig is the configuration for the pprof service.
type PprofConfig struct {
	// Enabled controls whether the pprof service is enabled.
	Enabled bool `json:"enabled"`

	// ListenAddress is the address to listen on.
	ListenAddress string `json:"listenAddress"`
}

// NewService creates a new pprof service.
func (pc *PprofConfig) NewService(logger *zap.Logger) *Service {
	return &Service{
		logger: logger,
		server: http.Server{
			Addr: pc.ListenAddress,
		},
	}
}

// Service implements [service.Service].
type Service struct {
	logger *zap.Logger
	server http.Server
}

// String implements [service.Service.String].
func (s *Service) String() string {
	return "pprof"
}

// Start implements [service.Service.Start].
func (s *Service) Start(ctx context.Context) error {
	var lc net.ListenConfig
	ln, err := lc.Listen(ctx, "tcp", s.server.Addr)
	if err != nil {
		return err
	}

	go func() {
		if err := s.server.Serve(ln); err != nil && err != http.ErrServerClosed {
			s.logger.Error("Failed to serve pprof", zap.Error(err))
		}
	}()

	s.logger.Info("Started pprof", zap.String("listenAddress", s.server.Addr))
	return nil
}

// Stop implements [service.Service.Stop].
func (s *Service) Stop() error {
	return s.server.Close()
}
