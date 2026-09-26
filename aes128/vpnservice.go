package main

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/go-ping/ping"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
	"runtime"
	"vpnpb"
)

const (
	currentVersion  = "1.0.3"
	apiBaseURL      = "https://client.aes.cx/api"
	appDataFileName = "app_data.bin"
	tokenFileName   = "token.bin"
	serviceName     = "AES128VPNService"
)

var ErrUnauthorized = errors.New("unauthorized")

var ipCheckEndpoints = []string{
	"https://ipinfo.io/json",
	"https://api.ipify.org?format=json",
}

type VPNService struct {
	httpClient    *http.Client
	ipClient      *http.Client
	grpcConn      *grpc.ClientConn
	grpcClient    vpnpb.VPNControlClient
	serviceToken  string
	encryptionKey []byte
	appData       AppData
	dataLock      sync.RWMutex
	storageLock   sync.Mutex
	loginLock     sync.Mutex
	keyLock       sync.Mutex
	shutdownOnce  sync.Once
}

type AppData struct {
	UserData             interface{}    `json:"userData"`
	Locations            []LocationInfo `json:"locations"`
	UserUUID             string         `json:"user_uuid"`
	SessionName          string         `json:"sessionName"`
	LatestAppVersion     string         `json:"latestAppVersion"`
	Protocol             string         `json:"protocol"`
	IsMini               bool           `json:"isMini"`
	EnableTor            bool           `json:"enableTor"`
	UseCustomLink        bool           `json:"useCustomLink"`
	CustomV2rayLink      string         `json:"customV2rayLink"`
	SelectedLocationName string         `json:"selectedLocationName"`
	SplitTunnelEnabled   bool           `json:"splitTunnelEnabled"`
	SplitTunnelDomains   string         `json:"splitTunnelDomains"`
	SplitTunnelDiscord   bool           `json:"splitTunnelDiscord"`
	SplitTunnelSteam     bool           `json:"splitTunnelSteam"`
	SplitTunnelCustom    string         `json:"splitTunnelCustom"`
	SplitTunnelMode      string         `json:"splitTunnelMode"`
	AutoStart            bool           `json:"autoStart"`
	AutoConnect          bool           `json:"autoConnect"`
	KillSwitch           bool           `json:"killSwitch"`
}

type LocationInfo struct {
	Name               string `json:"name"`
	Domain             string `json:"domain"`
	IPAddress          string `json:"ip_address"`
	VlessXhttpPort     int    `json:"vless_xhttp_port"`
	VmessPort          int    `json:"vmess_port"`
	TrojanPort         int    `json:"trojan_port"`
	VlessXTLSPort      int    `json:"vless_xtls_port"`
	RealityPK          string `json:"reality_pk"`
	VlessRealityPort   int    `json:"vless_reality_port"`
	VlessXTLSTorPort   int    `json:"vless_xtls_tor_port"`
	HysteriaPort       int    `json:"hysteria_port"`
	HysteriaSalamander string `json:"hysteria_salamander"`
}

type LocationWithPing struct {
	Name      string `json:"name"`
	RttMillis int64  `json:"rttMillis"`
}

type universalIPInfo struct {
	IP          string  `json:"ip"`
	Query       string  `json:"query"`
	Country     string  `json:"country"`
	City        string  `json:"city"`
	CountryCode string  `json:"countryCode"`
	Lat         float64 `json:"lat"`
	Lon         float64 `json:"lon"`
}

type IPInfo struct {
	Query       string  `json:"query"`
	Country     string  `json:"country"`
	CountryCode string  `json:"countryCode"`
	City        string  `json:"city"`
	Lat         float64 `json:"lat"`
	Lon         float64 `json:"lon"`
}

type AppSessionInfo struct {
	ID   int64  `json:"id"`
	Name string `json:"name"`
}

type LoginResult struct {
	Success     bool             `json:"success"`
	Error       string           `json:"error,omitempty"`
	SessionName string           `json:"sessionName,omitempty"`
	Sessions    []AppSessionInfo `json:"sessions,omitempty"`
}

type DeleteSessionResult struct {
	Success  bool             `json:"success"`
	Error    string           `json:"error,omitempty"`
	Sessions []AppSessionInfo `json:"sessions,omitempty"`
}

type ApiResponse struct {
	AppSessionToken string           `json:"app_session_token"`
	SessionName     string           `json:"session_name"`
	Error           string           `json:"error"`
	Sessions        []AppSessionInfo `json:"sessions"`
	Status          string           `json:"status"`
}

type AppSettingsResponse struct {
	LatestAppVersion string `json:"latest_app_version"`
}

type StartupData struct {
	IsLoggedIn        bool    `json:"isLoggedIn"`
	InitialAppData    AppData `json:"initialAppData"`
	AppVersion        string  `json:"appVersion"`
	IsUpdateAvailable bool    `json:"isUpdateAvailable"`
	IPInfo            IPInfo  `json:"ipInfo"`
}

type UserInfoResponse struct {
	Status string      `json:"status"`
	User   interface{} `json:"user"`
}

type LocationsResponse struct {
	UserUUID  string         `json:"user_uuid"`
	Locations []LocationInfo `json:"locations"`
}

func NewVPNService() *VPNService {
	ipTransport := &http.Transport{
		DisableKeepAlives: true,
	}
	s := &VPNService{
		httpClient: &http.Client{Timeout: 10 * time.Second},
		ipClient:   &http.Client{Timeout: 5 * time.Second, Transport: ipTransport},
	}

	token, err := s.readServiceToken()
	if err == nil {
		s.serviceToken = token
	}
	key, err := getEncryptionKey()
	if err != nil {
		log.Printf("WARNING: Could not obtain encryption key: %v. Please ensure the service is installed correctly.", err)
	} else {
		s.encryptionKey = key
	}

	if err := s.connectGRPC(); err != nil {
		log.Printf("WARNING: Could not establish gRPC connection: %v", err)
	}

	return s
}

func (s *VPNService) connectGRPC() error {
	if s.grpcConn != nil {
		s.grpcConn.Close()
		s.grpcConn = nil
		s.grpcClient = nil
	}
	conn, err := grpc.NewClient(
		serviceGRPCAddr,
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		platformDialOption(),
	)
	if err != nil {
		return fmt.Errorf("failed to create gRPC client: %w", err)
	}
	s.grpcConn = conn
	s.grpcClient = vpnpb.NewVPNControlClient(conn)
	return nil
}

func (s *VPNService) grpcAuthContext() (context.Context, context.CancelFunc) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	if s.serviceToken != "" {
		ctx = metadata.AppendToOutgoingContext(ctx, "authorization", s.serviceToken)
	}
	return ctx, cancel
}

func (s *VPNService) grpcStartContext() (context.Context, context.CancelFunc) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	if s.serviceToken != "" {
		ctx = metadata.AppendToOutgoingContext(ctx, "authorization", s.serviceToken)
	}
	ctx = s.platformStartContext(ctx)
	return ctx, cancel
}

func statusResponseToJSON(resp *vpnpb.StatusResponse) string {
	result, _ := json.Marshal(map[string]interface{}{
		"isRunning": resp.GetIsRunning(),
		"message":   resp.GetMessage(),
	})
	return string(result)
}

func isConnectionError(err error) bool {
	if err == nil {
		return false
	}
	errStr := err.Error()
	return strings.Contains(errStr, "connection refused") ||
		strings.Contains(errStr, "unavailable") ||
		strings.Contains(errStr, "Unavailable") ||
		strings.Contains(errStr, "transport is closing") ||
		strings.Contains(errStr, "connection error")
}

func (s *VPNService) cleanupOldFiles() {
	filesToDelete := []string{"settings.bin", "token.cfg", "cache.json", "cache.bin", "app_data.bin", "token.bin"}

	oldConfigDir, err := os.UserConfigDir()
	if err == nil {
		oldAppConfigDir := filepath.Join(oldConfigDir, "aes128")
		for _, f := range filesToDelete {
			path := filepath.Join(oldAppConfigDir, f)
			os.Remove(path)
		}
		os.Remove(oldAppConfigDir)
	}

	filesToCleanInNewDir := []string{"settings.bin", "token.cfg", "cache.json", "cache.bin"}
	for _, f := range filesToCleanInNewDir {
		path, err := getConfigPath(f)
		if err == nil {
			os.Remove(path)
		}
	}
}

func encrypt(data []byte, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}
	ciphertext := gcm.Seal(nonce, nonce, data, nil)
	return ciphertext, nil
}

func decrypt(data []byte, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonceSize := gcm.NonceSize()
	if len(data) < nonceSize {
		return nil, errors.New("ciphertext too short")
	}
	nonce, ciphertext := data[:nonceSize], data[nonceSize:]
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, err
	}
	return plaintext, nil
}

func (s *VPNService) SaveAppData(appDataJson string) error {
	s.storageLock.Lock()
	defer s.storageLock.Unlock()
	var data AppData
	err := json.Unmarshal([]byte(appDataJson), &data)
	if err != nil {
		log.Printf("Failed to unmarshal app data into struct: %v", err)
		return fmt.Errorf("failed to parse app data: %w", err)
	}
	if err := s.writeEncryptedFile(appDataFileName, []byte(appDataJson)); err != nil {
		return err
	}
	s.dataLock.Lock()
	s.appData = data
	s.dataLock.Unlock()
	return nil
}

func (s *VPNService) LoadAppData() (string, error) {
	key, err := s.storageKey()
	if err != nil {
		return "", err
	}
	path, err := getConfigPath(appDataFileName)
	if err != nil {
		return "", fmt.Errorf("failed to get config path: %w", err)
	}
	encryptedData, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return "{}", nil
		}
		return "", fmt.Errorf("failed to read app data file: %w", err)
	}
	decryptedData, err := decrypt(encryptedData, key)
	if err != nil {
		log.Printf("Warning: Failed to decrypt app data, returning default. Error: %v", err)
		return "", fmt.Errorf("saved settings could not be decrypted (file preserved): %w", err)
	}
	return string(decryptedData), nil
}

func (s *VPNService) Shutdown() {
	s.shutdownOnce.Do(func() {
		if _, err := s.StopCore(); err != nil {
			log.Printf("Failed to stop VPN during shutdown: %v", err)
		}
		if s.grpcConn != nil {
			s.grpcConn.Close()
		}
	})
}

func (s *VPNService) FindFastestLocation() (string, error) {
	s.dataLock.RLock()
	locations := compatibleLocations(s.appData)
	s.dataLock.RUnlock()

	if len(locations) == 0 {
		return "Fastest server", fmt.Errorf("no servers support the selected protocol and Tor settings")
	}

	var wg sync.WaitGroup
	pingResults := make(chan struct {
		Name string
		Rtt  time.Duration
	}, len(locations))

	for _, loc := range locations {
		wg.Add(1)
		go func(location LocationInfo) {
			defer wg.Done()
			pinger, err := ping.NewPinger(location.IPAddress)
			if err != nil {
				return
			}
			pinger.Count = 1
			pinger.Timeout = time.Second * 1
			pinger.SetPrivileged(runtime.GOOS == "windows")
			err = pinger.Run()
			if err == nil && pinger.Statistics().PacketsRecv > 0 {
				pingResults <- struct {
					Name string
					Rtt  time.Duration
				}{Name: location.Name, Rtt: pinger.Statistics().AvgRtt}
			}
		}(loc)
	}

	wg.Wait()
	close(pingResults)

	var bestLocation string = "Fastest server"
	minRtt := time.Hour

	for result := range pingResults {
		if result.Rtt < minRtt {
			minRtt = result.Rtt
			bestLocation = result.Name
		}
	}

	if bestLocation == "Fastest server" {
		log.Printf("Warning: No successful pings, falling back to first compatible location: %s", locations[0].Name)
		return locations[0].Name, nil
	}

	return bestLocation, nil
}

func (s *VPNService) GetLocationsWithPing() ([]LocationWithPing, error) {
	s.dataLock.RLock()
	locations := compatibleLocations(s.appData)
	s.dataLock.RUnlock()
	if len(locations) == 0 {
		return nil, fmt.Errorf("no servers support the selected protocol and Tor settings")
	}
	var wg sync.WaitGroup
	resultsChan := make(chan LocationWithPing, len(locations))
	for _, loc := range locations {
		wg.Add(1)
		go func(location LocationInfo) {
			defer wg.Done()
			pinger, err := ping.NewPinger(location.IPAddress)
			if err != nil {
				resultsChan <- LocationWithPing{Name: location.Name, RttMillis: -1}
				return
			}
			pinger.Count = 1
			pinger.Timeout = time.Second * 1
			pinger.SetPrivileged(runtime.GOOS == "windows")
			err = pinger.Run()
			if err == nil && pinger.Statistics().PacketsRecv > 0 {
				resultsChan <- LocationWithPing{Name: location.Name, RttMillis: pinger.Statistics().AvgRtt.Milliseconds()}
			} else {
				resultsChan <- LocationWithPing{Name: location.Name, RttMillis: -1}
			}
		}(loc)
	}
	wg.Wait()
	close(resultsChan)
	var allResults []LocationWithPing
	for result := range resultsChan {
		allResults = append(allResults, result)
	}
	return allResults, nil
}

func compatibleLocations(data AppData) []LocationInfo {
	var result []LocationInfo
	for _, loc := range data.Locations {
		port := loc.VlessXhttpPort
		if data.Protocol == "vless-xtls" {
			port = loc.VlessXTLSPort
		}
		if data.Protocol == "hysteria2" {
			port = loc.HysteriaPort
		}
		if data.EnableTor {
			port = loc.VlessXTLSTorPort
		}
		if port > 0 && port <= 65535 {
			result = append(result, loc)
		}
	}
	return result
}

func (s *VPNService) ensureGRPCClient() error {
	if s.grpcClient != nil {
		return nil
	}
	return s.connectGRPC()
}

func (s *VPNService) StartCore() (string, error) {
	if s.serviceToken == "" {
		return "", fmt.Errorf("service token is not loaded")
	}
	if err := s.ensureGRPCClient(); err != nil {
		return "", fmt.Errorf("gRPC client not available: %w", err)
	}

	ctx, cancel := s.grpcStartContext()
	defer cancel()

	resp, err := s.grpcClient.Start(ctx, &vpnpb.StartRequest{})
	if err != nil {
		if isConnectionError(err) {
			log.Println("Connection refused. Attempting to start service...")
			startErr := s.ensureServiceIsRunning()
			if startErr != nil {
				log.Printf("Failed to start service: %v", startErr)
				return "", fmt.Errorf("service stopped, failed to start: %w", startErr)
			}
			log.Println("Service start initiated. Retrying gRPC...")
			s.grpcConn.Connect()
			ctx2, cancel2 := s.grpcStartContext()
			defer cancel2()
			resp, err = s.grpcClient.Start(ctx2, &vpnpb.StartRequest{}, grpc.WaitForReady(true))
			if err != nil {
				return "", fmt.Errorf("service restarted, but gRPC call failed: %w", err)
			}
		} else {
			return "", err
		}
	}

	return statusResponseToJSON(resp), nil
}

func (s *VPNService) StopCore() (string, error) {
	if s.serviceToken == "" {
		log.Println("Warning: Service token not loaded, attempting to stop core anyway.")
	}
	if err := s.ensureGRPCClient(); err != nil {
		return `{"status":"stopped or not running"}`, nil
	}

	ctx, cancel := s.grpcAuthContext()
	defer cancel()

	resp, err := s.grpcClient.Stop(ctx, &vpnpb.StopRequest{})
	if err != nil {
		if isConnectionError(err) {
			log.Println("StopCore: Connection refused, assuming service is not running.")
			return `{"status":"stopped or not running"}`, nil
		}
		return "", err
	}

	return statusResponseToJSON(resp), nil
}

func (s *VPNService) GetCoreStatus() (string, error) {
	if s.serviceToken == "" {
		return `{"isRunning": false, "error": "service token not loaded"}`, nil
	}
	if err := s.ensureGRPCClient(); err != nil {
		return `{"isRunning": false, "error": "gRPC client not available"}`, nil
	}

	ctx, cancel := s.grpcAuthContext()
	defer cancel()

	resp, err := s.grpcClient.GetStatus(ctx, &vpnpb.StatusRequest{})
	if err != nil {
		if isConnectionError(err) {
			return `{"isRunning": false, "error": "connection refused"}`, nil
		}
		return "", err
	}

	return statusResponseToJSON(resp), nil
}

func (s *VPNService) GetMyIP() IPInfo {
	checkCtx, checkCancel := context.WithTimeout(context.Background(), 6*time.Second)
	defer checkCancel()
	var lastErr error
	for _, endpoint := range ipCheckEndpoints {
		ctx, cancel := context.WithTimeout(checkCtx, 3*time.Second)
		req, err := http.NewRequestWithContext(ctx, "GET", endpoint, nil)
		if err != nil {
			cancel()
			lastErr = fmt.Errorf("failed to create request for %s: %w", endpoint, err)
			continue
		}

		resp, err := s.ipClient.Do(req)
		if err != nil {
			cancel()
			lastErr = fmt.Errorf("failed to get IP from %s: %w", endpoint, err)
			continue
		}

		bodyBytes, readErr := io.ReadAll(resp.Body)
		resp.Body.Close()
		cancel()
		if readErr != nil {
			lastErr = fmt.Errorf("failed to read body from %s: %w", endpoint, readErr)
			continue
		}

		if resp.StatusCode != http.StatusOK {
			lastErr = fmt.Errorf("non-200 status %d from %s: %s", resp.StatusCode, endpoint, string(bodyBytes))
			continue
		}

		var tempInfo universalIPInfo
		if json.Unmarshal(bodyBytes, &tempInfo) == nil {
			finalIP := tempInfo.IP
			if tempInfo.Query != "" {
				finalIP = tempInfo.Query
			}

			finalCountryCode := tempInfo.CountryCode
			if finalCountryCode == "" && len(tempInfo.Country) == 2 {
				if _, err := fmt.Sscanf(tempInfo.Country, "%d", new(int)); err != nil {
					finalCountryCode = tempInfo.Country
				}
			}

			if finalIP != "" {
				return IPInfo{
					Query:       finalIP,
					Country:     tempInfo.Country,
					CountryCode: finalCountryCode,
					City:        tempInfo.City,
					Lat:         tempInfo.Lat,
					Lon:         tempInfo.Lon,
				}
			}
		}

		var ipifyInfo struct {
			Ip string `json:"ip"`
		}
		if json.Unmarshal(bodyBytes, &ipifyInfo) == nil && ipifyInfo.Ip != "" {
			return IPInfo{Query: ipifyInfo.Ip}
		}

		lastErr = fmt.Errorf("failed to parse response from %s: %s", endpoint, string(bodyBytes))
	}

	log.Printf("Error getting IP after trying all endpoints: %v", lastErr)
	return IPInfo{}
}

func freshIPCheck() IPInfo {
	checkCtx, checkCancel := context.WithTimeout(context.Background(), 6*time.Second)
	defer checkCancel()
	client := &http.Client{
		Timeout:   6 * time.Second,
		Transport: &http.Transport{DisableKeepAlives: true},
	}
	for _, endpoint := range ipCheckEndpoints {
		ctx, cancel := context.WithTimeout(checkCtx, 3*time.Second)
		req, err := http.NewRequestWithContext(ctx, "GET", endpoint, nil)
		if err != nil {
			cancel()
			continue
		}
		resp, err := client.Do(req)
		if err != nil {
			cancel()
			continue
		}
		bodyBytes, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		cancel()
		if resp.StatusCode != http.StatusOK {
			continue
		}
		var tempInfo universalIPInfo
		if json.Unmarshal(bodyBytes, &tempInfo) == nil {
			ip := tempInfo.IP
			if tempInfo.Query != "" {
				ip = tempInfo.Query
			}
			cc := tempInfo.CountryCode
			if cc == "" && len(tempInfo.Country) == 2 {
				cc = tempInfo.Country
			}
			if ip != "" {
				return IPInfo{
					Query:       ip,
					Country:     tempInfo.Country,
					CountryCode: cc,
					City:        tempInfo.City,
					Lat:         tempInfo.Lat,
					Lon:         tempInfo.Lon,
				}
			}
		}
		var ipifyInfo struct {
			Ip string `json:"ip"`
		}
		if json.Unmarshal(bodyBytes, &ipifyInfo) == nil && ipifyInfo.Ip != "" {
			return IPInfo{Query: ipifyInfo.Ip}
		}
	}
	return IPInfo{}
}

type ConnectionStatus struct {
	Connected bool   `json:"connected"`
	IPChanged bool   `json:"ipChanged"`
	IPInfo    IPInfo `json:"ipInfo"`
	Message   string `json:"message"`
}

func (s *VPNService) WaitForConnection(oldIP string) ConnectionStatus {
	s.dataLock.RLock()
	selective := s.appData.SplitTunnelEnabled && s.appData.SplitTunnelMode == "tunnel"
	s.dataLock.RUnlock()
	var lastInfo IPInfo
	for attempt := 0; attempt < 3; attempt++ {
		statusJSON, err := s.GetCoreStatus()
		var status struct {
			IsRunning bool `json:"isRunning"`
		}
		if err != nil || json.Unmarshal([]byte(statusJSON), &status) != nil || !status.IsRunning {
			return ConnectionStatus{Message: "VPN core is not running"}
		}
		lastInfo = freshIPCheck()
		changed := oldIP != "" && lastInfo.Query != "" && lastInfo.Query != oldIP
		if changed || (selective && lastInfo.Query != "" && s.verifyProxyTraffic()) {
			return ConnectionStatus{Connected: true, IPChanged: changed, IPInfo: lastInfo, Message: "connected"}
		}
		if attempt < 2 {
			time.Sleep(time.Second)
		}
	}

	s.StopCore()
	return ConnectionStatus{Connected: false, IPInfo: lastInfo, Message: "VPN traffic could not be verified; disconnected"}
}

func (s *VPNService) saveToken(token string) error {
	if strings.TrimSpace(token) == "" {
		return errors.New("server returned an empty session token")
	}
	return s.writeEncryptedFile(tokenFileName, []byte(token))
}

func (s *VPNService) readToken() (string, error) {
	key, err := s.storageKey()
	if err != nil {
		return "", err
	}
	path, err := getConfigPath(tokenFileName)
	if err != nil {
		return "", err
	}
	encryptedToken, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return "", nil
		}
		return "", err
	}
	decryptedToken, err := decrypt(encryptedToken, key)
	if err != nil {
		log.Printf("Warning: Failed to decrypt saved token: %v", err)
		return "", fmt.Errorf("failed to decrypt token: %w", err)
	}
	return string(decryptedToken), nil
}

func (s *VPNService) deleteToken() error {
	path, err := getConfigPath(tokenFileName)
	if err != nil {
		log.Printf("Error getting token path for deletion: %v", err)
		return err
	}
	err = os.Remove(path)
	if err != nil && !os.IsNotExist(err) {
		log.Printf("Error deleting token file: %v", err)
		return err
	}
	return nil
}

func (s *VPNService) LogoutAndForget() error {
	s.storageLock.Lock()
	defer s.storageLock.Unlock()
	token, err := s.readToken()
	if err == nil && token != "" {
		go func() {
			reqCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			req, reqErr := http.NewRequestWithContext(reqCtx, "POST", fmt.Sprintf("%s/app/logout", apiBaseURL), nil)
			if reqErr == nil {
				req.Header.Set("X-App-Session-Token", token)
				req.Header.Set("Content-Type", "application/json")
				if resp, err := s.httpClient.Do(req); err == nil {
					resp.Body.Close()
				}
			}
		}()
	} else if err != nil {
		log.Printf("Could not read token during logout: %v", err)
	}

	delTokenErr := s.deleteToken()

	path, dataPathErr := getConfigPath(appDataFileName)
	var delDataErr error
	if dataPathErr == nil {
		delDataErr = os.Remove(path)
		if delDataErr != nil && !os.IsNotExist(delDataErr) {
			log.Printf("Error deleting app data file: %v", delDataErr)
		}
	} else {
		log.Printf("Error getting app data path for deletion: %v", dataPathErr)
	}

	s.dataLock.Lock()
	s.appData = AppData{}
	s.dataLock.Unlock()

	if delTokenErr != nil {
		return delTokenErr
	}
	if dataPathErr != nil {
		return dataPathErr
	}
	if delDataErr != nil && !os.IsNotExist(delDataErr) {
		return delDataErr
	}

	return nil
}

func (s *VPNService) BrowserOpenURL(url string) {
	if mainApp != nil {
		mainApp.Browser.OpenURL(url)
	}
}

func (s *VPNService) SetMiniMode(isMini bool) {
	if mainWindow == nil {
		return
	}
	if isMini {
		mainWindow.SetSize(380, 600)
		mainWindow.SetMinSize(380, 600)
		mainWindow.SetMaxSize(380, 600)
	} else {
		mainWindow.SetMinSize(1000, 600)
		mainWindow.SetMaxSize(1000, 600)
		mainWindow.SetSize(1000, 600)
	}
}

func (s *VPNService) LoadFile() (string, error) {
	if mainApp == nil {
		return "", errors.New("app not available")
	}
	selection, err := mainApp.Dialog.OpenFile().
		SetTitle("Load Domains").
		AddFilter("Text Files (*.txt)", "*.txt").
		AttachToWindow(mainWindow).
		PromptForSingleSelection()
	if err != nil {
		return "", err
	}
	if selection == "" {
		return "", nil
	}
	data, err := os.ReadFile(selection)
	if err != nil {
		return "", fmt.Errorf("failed to read file '%s': %w", selection, err)
	}
	return string(data), nil
}

func (s *VPNService) StartupCheck() StartupData {
	startupResult := StartupData{AppVersion: currentVersion}

	appDataJson, _ := s.LoadAppData()
	defaults := AppData{
		Protocol:             "vless-xhttp",
		SelectedLocationName: "Fastest server",
		SplitTunnelMode:      "exclude",
	}
	tempData := defaults
	if err := json.Unmarshal([]byte(appDataJson), &tempData); err != nil {
		log.Printf("Warning: Could not unmarshal saved app data, using defaults. Error: %v", err)
	}
	s.dataLock.Lock()
	s.appData = tempData
	s.dataLock.Unlock()

	startupResult.InitialAppData = tempData

	token, tokenErr := s.readToken()
	if tokenErr != nil || token == "" {
		if tokenErr != nil {
			log.Printf("Error reading token on startup: %v", tokenErr)
		}
		startupResult.IsLoggedIn = false
		return startupResult
	}
	startupResult.IsLoggedIn = true

	ipChan := make(chan IPInfo, 1)
	go func() { ipChan <- s.GetMyIP() }()

	var wg sync.WaitGroup
	var sessionNameData, userInfo, locationsData, appSettingsData []byte
	var sessionErr, userErr, locErr, appSettingsErr error

	apiCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	wg.Add(4)
	go func() {
		defer wg.Done()
		appSettingsData, appSettingsErr = s.getAuthenticatedDataWithContext(apiCtx, token, "/app/settings")
	}()
	go func() {
		defer wg.Done()
		sessionNameData, sessionErr = s.getAuthenticatedDataWithContext(apiCtx, token, "/app/sessions/current")
	}()
	go func() {
		defer wg.Done()
		userInfo, userErr = s.getAuthenticatedDataWithContext(apiCtx, token, "/app/account_info")
	}()
	go func() {
		defer wg.Done()
		locationsData, locErr = s.getAuthenticatedDataWithContext(apiCtx, token, "/app/locations")
	}()
	wg.Wait()

	if errors.Is(userErr, ErrUnauthorized) {
		log.Println("StartupCheck: Account info returned Unauthorized, token is invalid. Logging out.")
		s.LogoutAndForget()
		startupResult.IsLoggedIn = false
		startupResult.IPInfo = <-ipChan
		return startupResult
	}

	for _, e := range []error{sessionErr, userErr, locErr, appSettingsErr} {
		if e != nil {
			log.Printf("StartupCheck: API error: %v", e)
		}
	}

	s.storageLock.Lock()
	s.dataLock.Lock()

	var appSettings AppSettingsResponse
	if appSettingsErr == nil {
		appSettingsErr = json.Unmarshal(appSettingsData, &appSettings)
	}
	var sessionNameResp struct {
		Name string `json:"session_name"`
	}
	if sessionErr == nil {
		sessionErr = json.Unmarshal(sessionNameData, &sessionNameResp)
	}
	var parsedUser UserInfoResponse
	if userErr == nil {
		userErr = json.Unmarshal(userInfo, &parsedUser)
		if parsedUser.User == nil {
			userErr = errors.New("account response has no user")
		}
	}
	var parsedLocations LocationsResponse
	if locErr == nil {
		locErr = json.Unmarshal(locationsData, &parsedLocations)
		if parsedLocations.UserUUID == "" {
			locErr = errors.New("locations response has no user identifier")
		}
	}

	if locErr == nil {
		s.appData.Locations = parsedLocations.Locations
		s.appData.UserUUID = parsedLocations.UserUUID
	}
	if appSettingsErr == nil && strings.TrimSpace(appSettings.LatestAppVersion) != "" {
		s.appData.LatestAppVersion = strings.TrimSpace(appSettings.LatestAppVersion)
	}
	if sessionErr == nil && sessionNameResp.Name != "" {
		s.appData.SessionName = sessionNameResp.Name
	}
	if userErr == nil {
		s.appData.UserData = parsedUser.User
	}

	startupResult.InitialAppData = s.appData
	appDataToSave, marshalErr := json.Marshal(s.appData)
	s.dataLock.Unlock()
	if marshalErr == nil {
		if err := s.writeEncryptedFile(appDataFileName, appDataToSave); err != nil {
			log.Printf("Error saving refreshed app data: %v", err)
		}
	}
	s.storageLock.Unlock()
	startupResult.IsUpdateAvailable = isNewerVersion(startupResult.InitialAppData.LatestAppVersion, currentVersion)

	startupResult.IPInfo = <-ipChan
	return startupResult
}

func (s *VPNService) getAuthenticatedDataWithContext(ctx context.Context, token, endpoint string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", fmt.Sprintf("%s%s", apiBaseURL, endpoint), nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request for %s: %w", endpoint, err)
	}
	req.Header.Set("X-App-Session-Token", token)
	req.Header.Set("Content-Type", "application/json")

	resp, err := s.httpClient.Do(req)
	if err != nil {
		if errors.Is(err, context.DeadlineExceeded) {
			return nil, fmt.Errorf("API request timeout for %s: %w", endpoint, err)
		}
		return nil, fmt.Errorf("HTTP request failed for %s: %w", endpoint, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
		return nil, ErrUnauthorized
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response body for %s: %w", endpoint, err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("API for %s returned status %d: %s", endpoint, resp.StatusCode, string(body))
	}

	return body, nil
}

func (s *VPNService) Login(username, password string) LoginResult {
	s.loginLock.Lock()
	defer s.loginLock.Unlock()
	username = strings.TrimSpace(username)
	if username == "" || password == "" {
		return LoginResult{Error: "Enter your username and password."}
	}
	if err := s.checkSessionStorage(); err != nil {
		log.Printf("Session storage check failed: %v", err)
		return LoginResult{Error: "Cannot save a session on this Mac. Please repair or reinstall AES128 VPN using the latest installer."}
	}
	reqCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	payload, _ := json.Marshal(map[string]string{
		"username": username,
		"password": password,
	})
	req, err := http.NewRequestWithContext(reqCtx, "POST", fmt.Sprintf("%s/app/login", apiBaseURL), bytes.NewBuffer(payload))
	if err != nil {
		return LoginResult{Success: false, Error: "Could not create request."}
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := s.httpClient.Do(req)
	if err != nil {
		if errors.Is(err, context.DeadlineExceeded) {
			return LoginResult{Success: false, Error: "Login request timed out."}
		}
		return LoginResult{Success: false, Error: "Network Error: Could not connect to the authentication service."}
	}
	defer resp.Body.Close()

	var apiResp ApiResponse
	bodyBytes, readErr := io.ReadAll(resp.Body)
	if readErr != nil {
		return LoginResult{Success: false, Error: "Failed to read server response."}
	}

	if err := json.Unmarshal(bodyBytes, &apiResp); err != nil {
		if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusConflict {
			return LoginResult{Success: false, Error: fmt.Sprintf("Authentication service returned HTTP %d. Please try again later.", resp.StatusCode)}
		}
		return LoginResult{Success: false, Error: "Failed to parse server response."}
	}

	if resp.StatusCode == http.StatusConflict {
		return LoginResult{Success: false, Error: apiResp.Error, Sessions: apiResp.Sessions}
	}
	if resp.StatusCode != http.StatusOK {
		if apiResp.Error != "" {
			return LoginResult{Success: false, Error: apiResp.Error}
		}
		return LoginResult{Success: false, Error: fmt.Sprintf("Authentication failed (Status %d)", resp.StatusCode)}
	}

	if strings.TrimSpace(apiResp.AppSessionToken) == "" {
		return LoginResult{Error: "Authentication service returned an invalid session."}
	}
	s.storageLock.Lock()
	defer s.storageLock.Unlock()
	if err := s.saveToken(apiResp.AppSessionToken); err != nil {
		log.Printf("CRITICAL: Login succeeded but failed to save token: %v", err)

		s.revokeSession(apiResp.AppSessionToken)
		return LoginResult{Success: false, Error: "Login successful, but could not save session locally."}
	}

	s.dataLock.Lock()
	s.appData.SessionName = apiResp.SessionName
	appDataToSave, marshalErr := json.Marshal(s.appData)
	s.dataLock.Unlock()
	if marshalErr == nil {
		if err := s.writeEncryptedFile(appDataFileName, appDataToSave); err != nil {
			log.Printf("Could not cache session name: %v", err)
		}
	}

	return LoginResult{Success: true, SessionName: apiResp.SessionName}
}

func (s *VPNService) DeleteSessionWithCredentials(username, password string, sessionIDToDelete int64) DeleteSessionResult {
	reqCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	payload, _ := json.Marshal(map[string]interface{}{
		"username":             username,
		"password":             password,
		"session_id_to_delete": sessionIDToDelete,
	})
	req, err := http.NewRequestWithContext(reqCtx, "POST", fmt.Sprintf("%s/app/delete-session", apiBaseURL), bytes.NewBuffer(payload))
	if err != nil {
		return DeleteSessionResult{Success: false, Error: "Could not create request."}
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := s.httpClient.Do(req)
	if err != nil {
		if errors.Is(err, context.DeadlineExceeded) {
			return DeleteSessionResult{Success: false, Error: "Delete session request timed out."}
		}
		return DeleteSessionResult{Success: false, Error: "Connection to authentication service failed."}
	}
	defer resp.Body.Close()

	var apiResp ApiResponse
	bodyBytes, readErr := io.ReadAll(resp.Body)
	if readErr != nil {
		return DeleteSessionResult{Success: false, Error: "Failed to read server response."}
	}
	if err := json.Unmarshal(bodyBytes, &apiResp); err != nil {
		if resp.StatusCode != http.StatusOK {
			return DeleteSessionResult{Success: false, Error: fmt.Sprintf("Authentication service returned HTTP %d. Please try again later.", resp.StatusCode)}
		}
		return DeleteSessionResult{Success: false, Error: "Failed to parse server response."}
	}

	if resp.StatusCode != http.StatusOK {
		if apiResp.Error != "" {
			return DeleteSessionResult{Success: false, Error: apiResp.Error}
		}
		return DeleteSessionResult{Success: false, Error: fmt.Sprintf("Failed to terminate session (Status %d)", resp.StatusCode)}
	}

	return DeleteSessionResult{Success: true, Sessions: apiResp.Sessions}
}

func (s *VPNService) ValidateSession() string {
	token, err := s.readToken()
	if err != nil || token == "" {
		if err != nil {
			log.Printf("ValidateSession: Error reading token: %v", err)
		}
		return "invalid"
	}

	valCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	_, err = s.getAuthenticatedDataWithContext(valCtx, token, "/app/account_info")

	if err != nil {
		if errors.Is(err, ErrUnauthorized) {
			log.Println("ValidateSession: Token is invalid (Unauthorized).")
			return "invalid"
		}
		log.Printf("ValidateSession: Error during validation call: %v", err)
		return "unknown"
	}

	return "valid"
}

func (s *VPNService) revokeSession(token string) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, apiBaseURL+"/app/logout", nil)
	if err != nil {
		return
	}
	req.Header.Set("X-App-Session-Token", token)
	resp, err := s.httpClient.Do(req)
	if err != nil {
		log.Printf("Could not release unsaved session: %v", err)
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		log.Printf("Could not release unsaved session: HTTP %d", resp.StatusCode)
	}
}

func isNewerVersion(latest, current string) bool {
	parse := func(value string) ([]int, bool) {
		parts := strings.Split(strings.TrimPrefix(strings.TrimSpace(value), "v"), ".")
		if len(parts) != 3 {
			return nil, false
		}
		result := make([]int, 3)
		for i, part := range parts {
			n, err := strconv.Atoi(part)
			if err != nil || n < 0 {
				return nil, false
			}
			result[i] = n
		}
		return result, true
	}
	l, lok := parse(latest)
	c, cok := parse(current)
	if !lok || !cok {
		return false
	}
	for i := range l {
		if l[i] != c[i] {
			return l[i] > c[i]
		}
	}
	return false
}
