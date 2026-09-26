package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"
	"vpnpb"
)

const stateDir = "/Library/Application Support/AES128 VPN/Helper"
const socketDir = "/var/run/com.aes128.vpn"

type localIdentity struct {
	uid uint32
	pid int
}

func (localIdentity) AuthType() string { return "unix-peer" }

type localCredentials struct {
	credentials.TransportCredentials
}

func (c localCredentials) ServerHandshake(conn net.Conn) (net.Conn, credentials.AuthInfo, error) {
	uc, ok := conn.(*net.UnixConn)
	if !ok {
		return nil, nil, errors.New("Unix socket required")
	}
	raw, err := uc.SyscallConn()
	if err != nil {
		return nil, nil, err
	}
	var cred *unix.Xucred
	var pid int
	var sockErr error
	err = raw.Control(func(fd uintptr) {
		cred, sockErr = unix.GetsockoptXucred(int(fd), unix.SOL_LOCAL, unix.LOCAL_PEERCRED)
		if sockErr == nil {
			pid, sockErr = unix.GetsockoptInt(int(fd), unix.SOL_LOCAL, unix.LOCAL_PEERPID)
		}
	})
	if err != nil || sockErr != nil || cred == nil {
		return nil, nil, errors.New("cannot authenticate peer")
	}
	st, err := os.Stat("/dev/console")
	if err != nil {
		return nil, nil, err
	}
	owner := st.Sys().(*syscall.Stat_t).Uid
	if owner == 0 || cred.Uid != owner {
		return nil, nil, errors.New("only the active console user may control VPN")
	}
	return conn, localIdentity{cred.Uid, pid}, nil
}
func identity(ctx context.Context) (localIdentity, error) {
	p, ok := peer.FromContext(ctx)
	if !ok {
		return localIdentity{}, errors.New("missing peer")
	}
	id, ok := p.AuthInfo.(localIdentity)
	if !ok {
		return id, errors.New("unauthenticated peer")
	}
	return id, nil
}

func authorizeConsoleRPC(consoleUser func() (uint32, error)) grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req interface{}, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (interface{}, error) {
		id, err := identity(ctx)
		if err != nil {
			return nil, status.Error(codes.Unauthenticated, "missing peer identity")
		}
		uid, err := consoleUser()
		if err != nil || uid == 0 || id.uid != uid {
			return nil, status.Error(codes.PermissionDenied, "only the active console user may control VPN")
		}
		return handler(ctx, req)
	}
}

func activeConsoleUID() (uint32, error) {
	st, err := os.Stat("/dev/console")
	if err != nil {
		return 0, err
	}
	return st.Sys().(*syscall.Stat_t).Uid, nil
}

type child struct {
	cmd  *exec.Cmd
	done chan struct{}
}
type vpnControlServer struct {
	vpnpb.UnimplementedVPNControlServer
	mu         sync.Mutex
	proxy, tun *child
	owner      localIdentity
	lease      time.Time
	running    bool
	message    string
	gateway    string
	failures   int
}

func command(timeout time.Duration, name string, args ...string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	return exec.CommandContext(ctx, name, args...).CombinedOutput()
}
func gatewaySignature() (string, error) {
	out, err := command(3*time.Second, "/sbin/route", "-n", "get", "default")
	if err != nil {
		return "", err
	}
	var parts []string
	for _, line := range strings.Split(string(out), "\n") {
		f := strings.Fields(line)
		if len(f) == 2 && (f[0] == "gateway:" || f[0] == "interface:") {
			parts = append(parts, f[1])
		}
	}
	if len(parts) != 2 {
		return "", errors.New("no default network")
	}
	return strings.Join(parts, "/"), nil
}
func executable(name string) string { return filepath.Join(stateDir, "cores", name) }

func launch(name, config string) (*child, error) {
	cmd := exec.Command(executable(name), "run", "-c", config)
	cmd.Dir = stateDir
	cmd.Env = []string{"PATH=/usr/bin:/bin:/usr/sbin:/sbin", "HOME=/var/root"}
	w := &rotatingLog{path: filepath.Join(stateDir, name+".log"), limit: 1024 * 1024}
	cmd.Stdout = w
	cmd.Stderr = w
	if err := cmd.Start(); err != nil {
		return nil, err
	}
	c := &child{cmd: cmd, done: make(chan struct{})}
	go func() { cmd.Wait(); close(c.done) }()
	return c, nil
}
func (c *child) alive() bool {
	if c == nil {
		return false
	}
	select {
	case <-c.done:
		return false
	default:
		return true
	}
}
func (c *child) stop() {
	if c == nil {
		return
	}
	c.cmd.Process.Signal(syscall.SIGTERM)
	select {
	case <-c.done:
	case <-time.After(4 * time.Second):
		c.cmd.Process.Kill()
		<-c.done
	}
}
func (s *vpnControlServer) stopLocked(reason string) error {
	s.running = false
	s.message = reason
	s.tun.stop()
	s.proxy.stop()
	s.tun = nil
	s.proxy = nil
	err := restoreDNS()
	if err != nil {
		s.message = reason + "; DNS restore pending: " + err.Error()
	}
	for _, name := range []string{"xray.json", "sing-box.json"} {
		os.Remove(filepath.Join(stateDir, name))
	}
	return err
}
func validateSettings(data *AppData) (*LocationInfo, error) {
	if data.KillSwitch {
		return nil, errors.New("kill switch is not available in this macOS build")
	}
	if len(data.Locations) > 1000 || len(data.CustomV2rayLink) > 8192 || len(data.SplitTunnelDomains) > 32768 {
		return nil, errors.New("settings exceed limits")
	}
	if _, err := splitTunnelRoute(data); err != nil {
		return nil, err
	}
	if data.UseCustomLink {
		if data.EnableTor {
			return nil, errors.New("Tor cannot be combined with a custom link")
		}
		_, loc, err := customXrayConfig(data.CustomV2rayLink)
		return loc, err
	}
	loc := findLocation(data.Locations, data.SelectedLocationName)
	if loc == nil {
		return nil, errors.New("select an available server")
	}
	if !validDomainSuffix(strings.ToLower(loc.Domain)) {
		return nil, errors.New("invalid server domain")
	}
	if len(data.UserUUID) > 128 || data.UserUUID == "" {
		return nil, errors.New("missing user identity")
	}
	port := 0
	switch data.Protocol {
	case "", "vless-xhttp":
		port = loc.VlessXhttpPort
		if data.EnableTor {
			return nil, errors.New("Tor requires XTLS")
		}
	case "vless-xtls":
		port = loc.VlessXTLSPort
		if data.EnableTor {
			port = loc.VlessXTLSTorPort
		}
	default:
		return nil, errors.New("unsupported protocol on macOS")
	}
	if port < 1 || port > 65535 {
		return nil, errors.New("server does not support the selected protocol or Tor")
	}
	return loc, nil
}
func proxyIP(ctx context.Context) (string, error) {
	u, _ := url.Parse("socks5://127.0.0.1:10808")
	tr := &http.Transport{Proxy: http.ProxyURL(u), DisableKeepAlives: true}
	defer tr.CloseIdleConnections()
	client := &http.Client{Transport: tr, Timeout: 7 * time.Second}
	req, _ := http.NewRequestWithContext(ctx, "GET", "https://api.ipify.org?format=json", nil)
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	var result struct {
		IP string `json:"ip"`
	}
	if resp.StatusCode != 200 {
		return "", errors.New("IP verification HTTP failure")
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1024)).Decode(&result); err != nil {
		return "", err
	}
	if net.ParseIP(result.IP) == nil {
		return "", errors.New("invalid public IP response")
	}
	return result.IP, nil
}
func (s *vpnControlServer) Start(ctx context.Context, req *vpnpb.StartRequest) (*vpnpb.StatusResponse, error) {
	id, err := identity(ctx)
	if err != nil {
		return nil, status.Error(codes.Unauthenticated, err.Error())
	}
	md, _ := metadata.FromIncomingContext(ctx)
	values := md.Get("aes128-config-bin")
	if len(values) != 1 || len(values[0]) > 256*1024 {
		return nil, status.Error(codes.InvalidArgument, "missing or oversized configuration")
	}
	var data AppData
	if err := json.Unmarshal([]byte(values[0]), &data); err != nil {
		return nil, status.Error(codes.InvalidArgument, "invalid configuration")
	}
	loc, err := validateSettings(&data)
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.stopLocked("reconnecting"); err != nil {
		return nil, status.Error(codes.Internal, err.Error())
	}
	if err := s.startLocked(ctx, &data, loc, id); err != nil {
		s.stopLocked("connection failed")
		return nil, status.Error(codes.Unavailable, err.Error())
	}
	s.running = true
	s.owner = id
	s.lease = time.Now()
	s.message = "verified VPN tunnel"
	s.failures = 0
	return &vpnpb.StatusResponse{IsRunning: true, Message: s.message}, nil
}
func (s *vpnControlServer) startLocked(ctx context.Context, data *AppData, loc *LocationInfo, id localIdentity) error {
	gw, err := gatewaySignature()
	if err != nil {
		return err
	}
	s.gateway = gw

	addresses, err := net.DefaultResolver.LookupIPAddr(ctx, loc.Domain)
	if err != nil || len(addresses) == 0 {
		return errors.New("cannot resolve VPN server")
	}
	var exclusions []string
	transportIP := ""
	for _, a := range addresses {
		if a.IP.To4() != nil {
			exclusions = append(exclusions, a.IP.String()+"/32")
			if transportIP == "" {
				transportIP = a.IP.String()
			}
		} else {
			exclusions = append(exclusions, a.IP.String()+"/128")
		}
	}
	if transportIP == "" {
		transportIP = addresses[0].IP.String()
	}
	var xconfig string
	if data.UseCustomLink {
		xconfig, _, err = customXrayConfig(data.CustomV2rayLink)
	} else if data.Protocol == "vless-xtls" {
		xconfig = generateXrayXTLSConfig(data, loc)
	} else {
		xconfig, err = generateXrayConfig(data, loc)
	}
	if err != nil {
		return err
	}
	var x map[string]interface{}
	if err = json.Unmarshal([]byte(xconfig), &x); err != nil {
		return err
	}
	outbound := x["outbounds"].([]interface{})[0].(map[string]interface{})
	outbound["settings"].(map[string]interface{})["vnext"].([]interface{})[0].(map[string]interface{})["address"] = transportIP
	xb, _ := json.MarshalIndent(x, "", "  ")
	sb, err := generateSingBoxConfig(data)
	if err != nil {
		return err
	}
	var box map[string]interface{}
	json.Unmarshal(sb, &box)
	box["inbounds"].([]interface{})[0].(map[string]interface{})["route_exclude_address"] = exclusions
	sb, _ = json.MarshalIndent(box, "", "  ")
	xp := filepath.Join(stateDir, "xray.json")
	bp := filepath.Join(stateDir, "sing-box.json")
	if err = os.WriteFile(xp, xb, 0600); err != nil {
		return err
	}
	if err = os.WriteFile(bp, sb, 0600); err != nil {
		return err
	}
	for _, v := range []struct {
		name string
		args []string
	}{{"xray", []string{"run", "-test", "-c", xp}}, {"sing-box", []string{"check", "-c", bp}}} {
		if out, err := command(5*time.Second, executable(v.name), v.args...); err != nil {
			log.Printf("%s rejected config: %s", v.name, out)
			return fmt.Errorf("%s configuration invalid", v.name)
		}
	}
	s.proxy, err = launch("xray", xp)
	if err != nil {
		return err
	}
	ready := false
	for i := 0; i < 30; i++ {
		if !s.proxy.alive() {
			return errors.New("Xray exited during startup")
		}
		c, e := net.DialTimeout("tcp", "127.0.0.1:10808", 100*time.Millisecond)
		if e == nil {
			c.Close()
			ready = true
			break
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(100 * time.Millisecond):
		}
	}
	if !ready {
		return errors.New("Xray listener did not become ready")
	}

	if _, err = proxyIP(ctx); err != nil {
		return fmt.Errorf("VPN server traffic check failed: %w", err)
	}
	s.tun, err = launch("sing-box", bp)
	if err != nil {
		return err
	}
	time.Sleep(time.Second)
	if !s.tun.alive() {
		return errors.New("TUN core exited during startup")
	}
	if err = installDNS(); err != nil {
		return err
	}
	if _, err = proxyIP(ctx); err != nil {
		return fmt.Errorf("VPN transport failed after TUN activation: %w", err)
	}
	return ctx.Err()
}
func (s *vpnControlServer) Stop(ctx context.Context, _ *vpnpb.StopRequest) (*vpnpb.StatusResponse, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.stopLocked("disconnected"); err != nil {
		return nil, status.Error(codes.Internal, err.Error())
	}
	return &vpnpb.StatusResponse{Message: s.message}, nil
}
func (s *vpnControlServer) GetStatus(ctx context.Context, _ *vpnpb.StatusRequest) (*vpnpb.StatusResponse, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	id, _ := identity(ctx)
	if id == s.owner {
		s.lease = time.Now()
	}
	return &vpnpb.StatusResponse{IsRunning: s.running, Message: s.message}, nil
}
func (s *vpnControlServer) watch(ctx context.Context) {
	tick := time.NewTicker(2 * time.Second)
	defer tick.Stop()
	s.watchTicks(ctx, tick.C)
}

func (s *vpnControlServer) watchTicks(ctx context.Context, ticks <-chan time.Time) {
	count := 0
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticks:
		}
		s.mu.Lock()
		count = (count + 1) % 5
		if s.running {
			reason := ""
			st, consoleErr := os.Stat("/dev/console")
			if consoleErr != nil || st.Sys().(*syscall.Stat_t).Uid != s.owner.uid {
				reason = "console user changed"
			}
			if !s.proxy.alive() || !s.tun.alive() {
				reason = "VPN core stopped"
			} else if time.Since(s.lease) > 45*time.Second || syscall.Kill(s.owner.pid, 0) != nil {
				reason = "client closed or suspended"
			}
			if reason == "" && count%5 == 0 {
				gw, err := gatewaySignature()
				if err != nil || gw != s.gateway {
					reason = "network changed; reconnect"
				}
				if reason == "" {
					probeCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
					_, probeErr := proxyIP(probeCtx)
					cancel()
					if probeErr != nil {
						s.failures++
					} else {
						s.failures = 0
					}
					if s.failures >= 2 {
						reason = "VPN transport lost; reconnect"
					}
				}
			}
			if reason != "" {
				log.Print(reason)
				s.stopLocked(reason)
			}
		}
		if !s.running && count%5 == 0 {
			if err := restoreDNS(); err != nil {
				log.Print("DNS recovery pending: ", err)
			}
		}
		s.mu.Unlock()
	}
}
func main() {
	if os.Geteuid() != 0 {
		log.Fatal("AES128 helper requires launchd root privileges")
	}
	unix.Umask(0077)
	if err := secureDirectory(filepath.Dir(stateDir), 0700); err != nil {
		log.Fatal(err)
	}
	if err := secureDirectory(stateDir, 0700); err != nil {
		log.Fatal(err)
	}
	if err := secureDirectory(socketDir, 0755); err != nil {
		log.Fatal(err)
	}
	os.Chmod(socketDir, 0755)
	if err := restoreDNS(); err != nil {
		log.Fatal("pending DNS recovery failed: ", err)
	}
	if err := installTrustedCores(); err != nil {
		log.Fatal(err)
	}
	path := filepath.Join(socketDir, "control.sock")
	os.Remove(path)
	listener, err := net.Listen("unix", path)
	if err != nil {
		log.Fatal(err)
	}

	if err = os.Chmod(path, 0666); err != nil {
		log.Fatal(err)
	}
	control := &vpnControlServer{message: "disconnected"}
	server := grpc.NewServer(grpc.Creds(localCredentials{insecure.NewCredentials()}), grpc.UnaryInterceptor(authorizeConsoleRPC(activeConsoleUID)), grpc.MaxRecvMsgSize(256*1024), grpc.MaxHeaderListSize(384*1024))
	vpnpb.RegisterVPNControlServer(server, control)
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer cancel()
	go control.watch(ctx)
	go func() { <-ctx.Done(); server.Stop(); listener.Close() }()
	log.Print("AES128 macOS helper ready")
	err = server.Serve(listener)
	control.mu.Lock()
	control.stopLocked("helper stopped")
	control.mu.Unlock()
	os.Remove(path)
	if err != nil && ctx.Err() == nil {
		log.Print(err)
	}
}
