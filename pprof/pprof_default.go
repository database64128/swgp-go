//go:build !swgpgo_nopprof

package pprof

import (
	"context"
	"log/slog"
	"net"
	"net/http"
	_ "net/http/pprof"

	"github.com/database64128/swgp-go/tslog"
)

func (c *Config) newService(logger *tslog.Logger) (*Service, error) {
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
	}, nil
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

type service struct {
	logger  *tslog.Logger
	network string
	server  http.Server
}

func (s *service) start(ctx context.Context) error {
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

func (s *service) stop() error {
	if err := s.server.Close(); err != nil {
		return err
	}
	s.logger.Info("Stopped pprof")
	return nil
}
