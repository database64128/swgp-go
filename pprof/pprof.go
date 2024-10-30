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
	return &Service{
		logger:  logger,
		network: network,
		server: http.Server{
			Addr: c.ListenAddress,
		},
	}
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
