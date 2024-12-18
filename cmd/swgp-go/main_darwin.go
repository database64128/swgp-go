//go:build darwin

package main

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"strings"
	"sync"
	"syscall"
	"time"
	"unsafe"

	"github.com/database64128/swgp-go/service"
	"go.uber.org/zap"
	"golang.org/x/net/route"
)

var (
	ErrInvalidGateway       = errors.New("invalid gateway address")
	rtmError          uint8 = 0x5 // RTM_ERROR, not exposed in syscall package
)

// GatewayMonitor handles gateway route monitoring and management
type GatewayMonitor struct {
	mu          sync.RWMutex
	ip          net.IP
	logger      *zap.Logger
	cfg         *service.Config
	ctx         context.Context
	cancel      context.CancelFunc
	interval    time.Duration
	routeSocket int
	seq         int32
}

// NewGatewayMonitor creates a new gateway monitor instance
func NewGatewayMonitor(cfg *service.Config, logger *zap.Logger, interval time.Duration) (*GatewayMonitor, error) {
	ctx, cancel := context.WithCancel(context.Background())

	// Open routing socket
	sock, err := syscall.Socket(syscall.AF_ROUTE, syscall.SOCK_RAW, syscall.AF_UNSPEC)
	if err != nil {
		cancel()
		return nil, fmt.Errorf("open route socket: %w", err)
	}

	// Set socket options
	err = syscall.SetsockoptInt(sock, syscall.SOL_SOCKET, syscall.SO_USELOOPBACK, 1)
	if err != nil {
		syscall.Close(sock)
		cancel()
		return nil, fmt.Errorf("set socket options: %w", err)
	}

	// Discover initial gateway IP
	monitor := &GatewayMonitor{
		cfg:         cfg,
		logger:      logger,
		interval:    interval,
		ctx:         ctx,
		cancel:      cancel,
		routeSocket: sock,
		seq:         1,
	}

	initialIP, err := monitor.discoverGateway()
	if err != nil {
		cancel()
		syscall.Close(sock)
		return nil, fmt.Errorf("discover initial gateway: %w", err)
	}
	monitor.ip = initialIP

	return monitor, nil
}

// roundup rounds up length to the nearest multiple of 4
func roundup(length int) int {
	if length == 0 {
		return 0
	}
	return ((length) + 3) &^ 3
}

func (g *GatewayMonitor) discoverGateway() (net.IP, error) {
	rib, err := route.FetchRIB(syscall.AF_INET, syscall.NET_RT_DUMP, 0)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch RIB: %v", err)
	}

	msgs, err := route.ParseRIB(syscall.NET_RT_DUMP, rib)
	if err != nil {
		return nil, fmt.Errorf("failed to parse RIB: %v", err)
	}

	var ips []net.IP

	for _, m := range msgs {
		if rm, ok := m.(*route.RouteMessage); ok {
			if rm.Flags&syscall.RTF_GATEWAY != 0 && rm.Flags&syscall.RTF_UP != 0 {
				addr := rm.Addrs[syscall.RTAX_GATEWAY]
				switch sa := addr.(type) {
				case *route.Inet4Addr:
					ip := net.IPv4(sa.IP[0], sa.IP[1], sa.IP[2], sa.IP[3])
					if isValidGateway(ip, g.logger) {
						ips = append(ips, ip)
					}
				case *route.Inet6Addr:
					ip := make(net.IP, net.IPv6len)
					copy(ip, sa.IP[:])
					if isValidGateway(ip, g.logger) {
						ips = append(ips, ip)
					}
				}
			}
		}
	}
	if len(ips) > 0 {
		g.logger.Info("Found gateway", zap.String("ip", ips[0].String()))
		return ips[0], nil
	}
	return nil, fmt.Errorf("no default gateway found")
}

func isValidGateway(ip net.IP, logger *zap.Logger) bool {
	if ip == nil || ip.Equal(net.IPv4zero) {
		logger.Debug("Invalid gateway: nil or zero IP")
		return false
	}

	// Check if it's a private network address (RFC 1918)
	privateNetworks := []string{
		"10.0.0.0/8",     // Class A
		"172.16.0.0/12",  // Class B
		"192.168.0.0/16", // Class C
		"169.254.0.0/16", // Link-local
	}

	for _, network := range privateNetworks {
		_, ipnet, err := net.ParseCIDR(network)
		if err != nil {
			logger.Error("Failed to parse CIDR", zap.String("network", network), zap.Error(err))
			continue
		}
		if ipnet.Contains(ip) {
			return true
		}
	}

	logger.Debug("Invalid gateway: not in private or link-local range", zap.String("ip", ip.String()))
	return false
}

func (g *GatewayMonitor) addRoute(dest net.IP, gateway net.IP, prefixLen int) error {
	if gateway.Equal(net.IPv4zero) {
		return fmt.Errorf("invalid gateway address: %v", gateway)
	}

	// Create routing message
	rtmsg := &syscall.RtMsghdr{
		Type:    syscall.RTM_ADD,
		Version: syscall.RTM_VERSION,
		Seq:     g.seq,
		Addrs:   syscall.RTA_DST | syscall.RTA_GATEWAY | syscall.RTA_NETMASK,
		Pid:     0, // Let kernel assign PID
		Flags:   syscall.RTF_UP | syscall.RTF_GATEWAY | syscall.RTF_STATIC,
	}
	g.seq++

	// Calculate total message size
	msgLen := syscall.SizeofRtMsghdr + syscall.SizeofSockaddrInet4*3 // Header + Dest + Gateway + Netmask

	// Create the message buffer
	wb := make([]byte, msgLen)

	// Copy header
	rtmsg.Msglen = uint16(msgLen)
	*(*syscall.RtMsghdr)(unsafe.Pointer(&wb[0])) = *rtmsg

	// Add destination sockaddr
	destAddr := syscall.RawSockaddrInet4{
		Len:    syscall.SizeofSockaddrInet4,
		Family: syscall.AF_INET,
	}
	copy(destAddr.Addr[:], dest.To4())
	destPos := syscall.SizeofRtMsghdr
	*(*syscall.RawSockaddrInet4)(unsafe.Pointer(&wb[destPos])) = destAddr

	// Add gateway sockaddr
	gwAddr := syscall.RawSockaddrInet4{
		Len:    syscall.SizeofSockaddrInet4,
		Family: syscall.AF_INET,
	}
	copy(gwAddr.Addr[:], gateway.To4())
	gwPos := destPos + syscall.SizeofSockaddrInet4
	*(*syscall.RawSockaddrInet4)(unsafe.Pointer(&wb[gwPos])) = gwAddr

	// Add netmask sockaddr
	maskAddr := syscall.RawSockaddrInet4{
		Len:    syscall.SizeofSockaddrInet4,
		Family: syscall.AF_INET,
	}
	// Create the netmask based on prefix length
	if prefixLen > 32 {
		prefixLen = 32
	}
	for i := 0; i < prefixLen/8; i++ {
		maskAddr.Addr[i] = 0xff
	}
	if prefixLen%8 != 0 {
		maskAddr.Addr[prefixLen/8] = ^byte(0xff >> uint(prefixLen%8))
	}
	maskPos := gwPos + syscall.SizeofSockaddrInet4
	*(*syscall.RawSockaddrInet4)(unsafe.Pointer(&wb[maskPos])) = maskAddr

	if _, err := syscall.Write(g.routeSocket, wb); err != nil {
		return fmt.Errorf("write route message: %w", err)
	}

	// Read response
	buf := make([]byte, os.Getpagesize())
	n, err := syscall.Read(g.routeSocket, buf)
	if err != nil {
		return fmt.Errorf("read route message: %w", err)
	}

	return g.handleRouteResponse(buf, n, "add")
}

func (g *GatewayMonitor) deleteRouteSyscall(dest net.IP) error {
	// Create routing message
	rtmsg := &syscall.RtMsghdr{
		Type:    syscall.RTM_DELETE,
		Version: syscall.RTM_VERSION,
		Seq:     g.seq,
		Addrs:   syscall.RTA_DST | syscall.RTA_NETMASK,
		Pid:     0,
		Flags:   syscall.RTF_UP | syscall.RTF_HOST | syscall.RTF_GATEWAY | syscall.RTF_STATIC,
	}
	g.seq++

	// Calculate total message size: header + destination + netmask
	msgLen := syscall.SizeofRtMsghdr + syscall.SizeofSockaddrInet4*2

	// Create message buffer
	wb := make([]byte, msgLen)

	// Copy header
	rtmsg.Msglen = uint16(msgLen)
	*(*syscall.RtMsghdr)(unsafe.Pointer(&wb[0])) = *rtmsg

	// Add destination sockaddr
	destAddr := syscall.RawSockaddrInet4{
		Len:    syscall.SizeofSockaddrInet4,
		Family: syscall.AF_INET,
	}
	copy(destAddr.Addr[:], dest.To4())
	destPos := syscall.SizeofRtMsghdr
	*(*syscall.RawSockaddrInet4)(unsafe.Pointer(&wb[destPos])) = destAddr

	// Add netmask sockaddr (full mask for host route)
	maskAddr := syscall.RawSockaddrInet4{
		Len:    syscall.SizeofSockaddrInet4,
		Family: syscall.AF_INET,
		Addr:   [4]byte{255, 255, 255, 255}, // /32 netmask
	}
	maskPos := destPos + syscall.SizeofSockaddrInet4
	*(*syscall.RawSockaddrInet4)(unsafe.Pointer(&wb[maskPos])) = maskAddr

	// Create a new route socket for deletion
	sock, err := syscall.Socket(syscall.AF_ROUTE, syscall.SOCK_RAW, syscall.AF_UNSPEC)
	if err != nil {
		return fmt.Errorf("create socket: %w", err)
	}
	defer syscall.Close(sock)

	// Set socket options
	err = syscall.SetsockoptInt(sock, syscall.SOL_SOCKET, syscall.SO_USELOOPBACK, 1)
	if err != nil {
		return fmt.Errorf("set socket options: %w", err)
	}

	// Write the delete message
	if _, err := syscall.Write(sock, wb); err != nil {
		return fmt.Errorf("write route message: %w", err)
	}

	// Read response
	rb := make([]byte, os.Getpagesize())
	n, err := syscall.Read(sock, rb)
	if err != nil {
		return fmt.Errorf("read route message: %w", err)
	}

	if n < syscall.SizeofRtMsghdr {
		return fmt.Errorf("short read: got %d bytes", n)
	}

	// Parse response header
	rtm := (*syscall.RtMsghdr)(unsafe.Pointer(&rb[0]))
	if rtm.Version != syscall.RTM_VERSION {
		return fmt.Errorf("invalid routing message version: %d", rtm.Version)
	}

	// Check for errors
	if rtm.Type == rtmError {
		errno := *(*int32)(unsafe.Pointer(&rb[syscall.SizeofRtMsghdr]))
		if errno != 0 {
			if errno == int32(syscall.ESRCH) {
				// Route not found is not an error
				return nil
			}
			return fmt.Errorf("route delete failed: %w", syscall.Errno(errno))
		}
	}

	g.logger.Info("Successfully deleted route using syscall",
		zap.String("destination", dest.String()))
	return nil
}

func (g *GatewayMonitor) handleRouteResponse(buf []byte, n int, op string) error {
	if n < syscall.SizeofRtMsghdr {
		return fmt.Errorf("short read: got %d bytes", n)
	}

	rtm := (*syscall.RtMsghdr)(unsafe.Pointer(&buf[0]))
	if rtm.Version != syscall.RTM_VERSION {
		return fmt.Errorf("invalid routing message version: %d", rtm.Version)
	}

	// Check for errors first
	if rtm.Type == rtmError {
		errno := *(*int32)(unsafe.Pointer(&buf[syscall.SizeofRtMsghdr]))
		if errno != 0 {
			return fmt.Errorf("route %s failed: %w", op, syscall.Errno(errno))
		}
	}

	// Check message length after error check
	msgLen := int(rtm.Msglen)
	if msgLen > n {
		return fmt.Errorf("message length %d > read length %d", msgLen, n)
	}

	return nil
}

func (g *GatewayMonitor) verifyRoutesSyscall(gatewayIP net.IP) (map[string]bool, error) {
	g.logger.Info("Verifying routes using syscall")

	routes := make(map[string]bool)

	// Open a route socket
	fd, err := syscall.Socket(syscall.AF_ROUTE, syscall.SOCK_RAW, syscall.AF_UNSPEC)
	if err != nil {
		g.logger.Error("Failed to open route socket",
			zap.Error(err))
		return nil, err
	}
	defer syscall.Close(fd)

	// Get the routing table
	tab, err := syscall.RouteRIB(syscall.NET_RT_DUMP2, 0)
	if err != nil {
		g.logger.Error("Failed to get routing table",
			zap.Error(err))
		return nil, err
	}

	// Parse the routing messages
	msgs, err := syscall.ParseRoutingMessage(tab)
	if err != nil {
		g.logger.Error("Failed to parse routing messages",
			zap.Error(err))
		return nil, err
	}

	// Process each routing message
	for _, msg := range msgs {
		rmsg, ok := msg.(*syscall.RouteMessage)
		if !ok {
			continue
		}

		// Get addresses from the message
		data := rmsg.Data[:]
		for len(data) > 0 {
			alen := int(data[0])
			if alen < 4 {
				// Malformed address
				break
			}

			if len(data) < alen {
				// Message too short
				break
			}

			// For IPv4 addresses
			if alen >= 8 {
				ip := net.IP(data[4:8])
				if ip.Equal(gatewayIP) {
					routes[ip.String()] = true
				}
			}

			data = data[alen:]
		}
	}

	return routes, nil
}

// updateRoutes updates all client routes with the new gateway
func (g *GatewayMonitor) updateRoutes(gatewayIP net.IP) error {
	if gatewayIP == nil {
		return ErrInvalidGateway
	}

	g.logger.Info("Updating gateway routes", zap.String("gateway", gatewayIP.String()))

	for _, client := range g.cfg.Clients {
		clientAddr := client.ProxyEndpointAddress.IP()
		clientIP := net.IP(clientAddr.AsSlice())

		// First try to delete any existing route
		err := g.deleteRouteSyscall(clientIP)
		if err != nil {
			g.logger.Debug("Route deletion failed (may not exist)",
				zap.String("client", clientAddr.String()),
				zap.Error(err))
		}

		// Add the new route
		err = g.addRoute(clientIP, gatewayIP, 32)
		if err != nil {
			return fmt.Errorf("add route for client %s: %w", clientIP, err)
		}
	}

	return nil
}

func (g *GatewayMonitor) cleanup() {
	g.logger.Info("Cleaning up gateway routes")

	// Get current routes first
	routes, err := g.verifyRoutesSyscall(g.ip)
	if err != nil {
		g.logger.Warn("Failed to get current routes during cleanup", zap.Error(err))
	}

	maxRetries := 3
	for retry := 0; retry < maxRetries; retry++ {
		allDeleted := true

		for _, client := range g.cfg.Clients {
			clientAddr := client.ProxyEndpointAddress.IP()
			clientIP := net.IP(clientAddr.AsSlice())

			// Check if route exists
			if routes != nil {
				if _, exists := routes[clientIP.String()]; !exists {
					continue // Route doesn't exist, skip
				}
			}

			if err := g.deleteRouteSyscall(clientIP); err != nil {
				// Only log as error if it's not "no such route"
				if !strings.Contains(err.Error(), "no such process") {
					g.logger.Error("Failed to delete route",
						zap.String("client", clientAddr.String()),
						zap.Error(err))
					allDeleted = false
				}
			} else {
				g.logger.Info("Successfully deleted route",
					zap.String("client", clientAddr.String()))
			}
		}

		if allDeleted {
			g.logger.Info("All routes deleted successfully")
			return
		}

		// If not all routes were deleted, wait a bit and verify routes again
		time.Sleep(100 * time.Millisecond)
		routes, err = g.verifyRoutesSyscall(g.ip)
		if err != nil {
			g.logger.Warn("Failed to verify routes during cleanup retry",
				zap.Int("retry", retry+1),
				zap.Error(err))
		}
	}

	g.logger.Warn("Some routes may not have been deleted after all retries")
}

// Start begins monitoring the gateway
func (g *GatewayMonitor) Start() error {
	gatewayIP, err := g.discoverGateway()
	if err != nil {
		return fmt.Errorf("initial gateway discovery: %w", err)
	}

	if err := g.updateRoutes(gatewayIP); err != nil {
		return fmt.Errorf("initial route update: %w", err)
	}

	g.mu.Lock()
	g.ip = gatewayIP
	g.mu.Unlock()

	go g.watch()
	return nil
}

// Stop halts the gateway monitoring and cleans up routes
func (g *GatewayMonitor) Stop() {
	g.cancel()
	g.cleanup()
	syscall.Close(g.routeSocket)
}

func (g *GatewayMonitor) watch() {
	ticker := time.NewTicker(g.interval)
	defer ticker.Stop()

	var lastValidGateway net.IP
	var consecutiveErrors int

	for {
		select {
		case <-g.ctx.Done():
			return
		case <-ticker.C:
			ip, err := g.discoverGateway()
			if err != nil {
				consecutiveErrors++
				if consecutiveErrors > 3 {
					g.logger.Error("Failed to get gateway address", zap.Error(err))
				} else {
					g.logger.Debug("Temporary error getting gateway", zap.Error(err))
				}

				// If we have a last valid gateway, keep using it
				if lastValidGateway != nil {
					ip = lastValidGateway
				} else {
					continue
				}
			} else {
				consecutiveErrors = 0
			}

			g.mu.Lock()
			gatewayChanged := !ip.Equal(g.ip)
			if gatewayChanged {
				g.logger.Info("Gateway IP changed",
					zap.String("old", g.ip.String()),
					zap.String("new", ip.String()))

				// Delete old routes before updating the gateway IP
				g.logger.Info("Cleaning up old routes")
				g.cleanup()

				// Update gateway IP
				g.ip = ip
				lastValidGateway = ip

				// Add new routes
				if err := g.updateRoutes(ip); err != nil {
					g.logger.Error("Failed to update routes", zap.Error(err))
				}
			}
			g.mu.Unlock()
		}
	}
}

var monitor *GatewayMonitor

// Initialize sets up the gateway monitor
func initHook(cfg *service.Config, logger *zap.Logger) {
	var err error
	monitor, err = NewGatewayMonitor(cfg, logger, 10*time.Second)
	if err != nil {
		logger.Fatal("Failed to create gateway monitor", zap.Error(err))
	}

	if err := monitor.Start(); err != nil {
		logger.Fatal("Failed to start gateway monitor", zap.Error(err))
	}
}

// Cleanup performs necessary cleanup
func cleanupHook() {
	if monitor != nil {
		monitor.Stop()
	}
}
