// Diode Network Client
// Copyright 2021 Diode
// Licensed under the Diode License, Version 1.1
package main

import (
	"fmt"
	"net"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/diodechain/diode_client/command"
	"github.com/diodechain/diode_client/config"
	"github.com/diodechain/diode_client/rpc"
	"github.com/diodechain/diode_client/staticserver"
	"github.com/diodechain/diode_client/util"
)

const (
	httpPort = 80
)

var (
	publishCmd = &command.Command{
		Name:             "publish",
		HelpText:         `  Publish ports of the local device to the Diode Network.`,
		ExampleText:      `  diode publish -public 80:80 -public 8080:8080 -protected 3000:3000 -protected 3001:3001 -private 22:22,0x......,0x...... -private 33:33,0x......,0x......`,
		Run:              publishHandler,
		Type:             command.DaemonCommand,
		SingleConnection: true,
	}
	enableStaticServer = false
	staticServer       staticserver.StaticHTTPServer
	scfg               staticserver.Config
)

func init() {
	cfg := config.AppConfig

	publishCmd.Flag.Var(&cfg.PublicPublishedPorts, "public", "expose ports to public users, so that user could connect to")
	publishCmd.Flag.Var(&cfg.ProtectedPublishedPorts, "protected", "expose ports to protected users (in fleet contract), so that user could connect to")
	publishCmd.Flag.Var(&cfg.PrivatePublishedPorts, "private", "expose ports to private users, so that user could connect to")
	publishCmd.Flag.StringVar(&cfg.SocksServerHost, "proxy_host", "127.0.0.1", "host of socksd proxy server")
	publishCmd.Flag.IntVar(&cfg.SocksServerPort, "proxy_port", 1080, "port of socksd proxy server")
	publishCmd.Flag.BoolVar(&cfg.EnableSocksServer, "socksd", false, "enable socksd proxy server")
	publishCmd.Flag.BoolVar(&enableStaticServer, "http", false, "enable http static file server")
	publishCmd.Flag.StringVar(&scfg.RootDirectory, "http_dir", "", "the root directory of http static file server")
	publishCmd.Flag.StringVar(&scfg.Host, "http_host", "127.0.0.1", "the host of http static file server")
	publishCmd.Flag.IntVar(&scfg.Port, "http_port", 8080, "the port of http static file server")
	publishCmd.Flag.BoolVar(&scfg.Indexed, "indexed", false, "enable directory indexing in http static file server")
}

// Supporting ipv6 if sorrounded by [] otherwise assuming domain or ip4
const ip = `(\[?[0-9A-Fa-f:]*:[0-9A-Fa-f:]+(?:%[a-zA-Z0-9]+)?\]?|[0-9A-Za-z-]+\.[0-9A-Za-z\.-]+[0-9A-Za-z])`

var portPattern = regexp.MustCompile(`^(` + ip + `:)?(\d+)(:(\d*)(:(tcp|tls|udp))?)?$`)
var accessPattern = regexp.MustCompile(`^0x[a-fA-F0-9]{40}$`)

func parsePorts(portStrings []string, mode int) ([]*config.Port, error) {
	ports := []*config.Port{}
	for _, portString := range portStrings {
		segments := strings.Split(portString, ",")
		allowlist := make(map[util.Address]bool)
		for _, segment := range segments {
			portDef := portPattern.FindStringSubmatch(segment)
			if len(portDef) == 8 {
				srcHostStr, srcPortStr, toPortStr, protocol := portDef[2], portDef[3], portDef[5], portDef[7]

				if srcHostStr == "" {
					srcHostStr = "localhost"
				}
				srcHostStr = strings.Trim(srcHostStr, "[]")

				srcPort, err := strconv.Atoi(srcPortStr)
				if err != nil {
					return nil, err
				}
				if !util.IsPort(srcPort) {
					err = fmt.Errorf("src port number should be bigger than 1 and smaller than 65535")
					return nil, err
				}
				var toPort int
				if toPortStr == "" {
					toPort = srcPort
				} else {
					toPort, err = strconv.Atoi(toPortStr)
					if err != nil {
						err = fmt.Errorf("to port number expected but got: %v in %v", portDef[3], segment)
						return nil, err
					}
					if !util.IsPort(toPort) {
						err = fmt.Errorf("to port number should be bigger than 1 and smaller than 65535")
						return nil, err
					}
				}

				port := &config.Port{
					SrcHost:   srcHostStr,
					Src:       srcPort,
					To:        toPort,
					Mode:      mode,
					Protocol:  config.AnyProtocol,
					Allowlist: allowlist,
				}

				switch protocol {
				case "tls":
					port.Protocol = config.TLSProtocol
				case "tcp":
					port.Protocol = config.TCPProtocol
				case "udp":
					port.Protocol = config.UDPProtocol
				case "any":
					port.Protocol = config.AnyProtocol
				case "":
					port.Protocol = config.AnyProtocol
				default:
					err = fmt.Errorf("port unknown protocol %v in: %v", protocol, segment)
					return nil, err
				}
				ports = append(ports, port)
			} else {
				access := accessPattern.FindString(segment)
				if access == "" {
					err := fmt.Errorf("port format expected (<from_ip>:)<from_port>(:<to_port>:<protocol>) or <address> but got: %v", segment)
					return nil, err
				}

				addr, err := util.DecodeAddress(access)
				if err != nil {
					err = fmt.Errorf("port format couldn't parse port address: %v", segment)
					return nil, err
				}

				allowlist[addr] = true
			}
		}
	}

	for _, v := range ports {
		if mode == config.PublicPublishedMode && len(v.Allowlist) > 0 {
			err := fmt.Errorf("public port publishing does not support providing addresses")
			return nil, err
		}
		if mode == config.PrivatePublishedMode && len(v.Allowlist) == 0 {
			err := fmt.Errorf("private port publishing requires providing at least one address")
			return nil, err
		}
		// limit fleet address size when publish protected port
		if mode == config.ProtectedPublishedMode && len(v.Allowlist) > 5 {
			err := fmt.Errorf("fleet address size should not exceeds 5 when publish protected port")
			return nil, err
		}
	}

	return ports, nil
}

func parseBind(bind string) (*config.Bind, error) {
	elements := strings.Split(bind, ":")
	if len(elements) == 3 {
		elements = append(elements, "tls")
	}
	if len(elements) != 4 {
		return nil, fmt.Errorf("bind format expected <local_port>:<to_address>:<to_port>:(udp|tcp|tls) but got: %v", bind)
	}

	var err error
	ret := &config.Bind{
		To: elements[1],
	}
	ret.LocalPort, err = strconv.Atoi(elements[0])
	if err != nil {
		return nil, fmt.Errorf("bind local_port should be a number but is: %v in: %v", elements[0], bind)
	}

	if !util.IsSubdomain(ret.To) {
		return nil, fmt.Errorf("bind format to_address should be valid diode domain but got: %v", ret.To)
	}

	ret.ToPort, err = strconv.Atoi(elements[2])
	if err != nil {
		return nil, fmt.Errorf("bind to_port should be a number but is: %v in: %v", elements[2], bind)
	}

	if elements[3] == "tls" {
		ret.Protocol = config.TLSProtocol
	} else if elements[3] == "tcp" {
		ret.Protocol = config.TCPProtocol
	} else if elements[3] == "udp" {
		ret.Protocol = config.UDPProtocol
	} else {
		return nil, fmt.Errorf("bind protocol should be 'tls', 'tcp', 'udp' but is: %v in: %v", elements[3], bind)
	}

	return ret, nil
}

func publishHandler() (err error) {
	cfg := config.AppConfig
	portString := make(map[int]*config.Port)

	// copy to config
	ports, err := parsePorts(cfg.PublicPublishedPorts, config.PublicPublishedMode)
	if err != nil {
		return
	}
	for _, port := range ports {
		if portString[port.To] != nil {
			err = fmt.Errorf("public port specified twice: %v", port.To)
			return
		}
		portString[port.To] = port
	}
	ports, err = parsePorts(cfg.ProtectedPublishedPorts, config.ProtectedPublishedMode)
	if err != nil {
		return
	}
	for _, port := range ports {
		if portString[port.To] != nil {
			err = fmt.Errorf("port conflict between public and protected port: %v", port.To)
			return
		}
		portString[port.To] = port
	}
	ports, err = parsePorts(cfg.PrivatePublishedPorts, config.PrivatePublishedMode)
	if err != nil {
		return
	}
	for _, port := range ports {
		if portString[port.To] != nil {
			err = fmt.Errorf("port conflict with private port: %v", port.To)
			return
		}
		portString[port.To] = port
	}
	cfg.PublishedPorts = portString

	if enableStaticServer || len(scfg.RootDirectory) > 0 {
		// publish the static when user didn't publish 80 port
		if _, ok := cfg.PublishedPorts[httpPort]; !ok {
			staticServer = staticserver.NewStaticHTTPServer(scfg)
			var ln net.Listener
			ln, err = net.Listen("tcp", staticServer.Addr)
			if err != nil {
				return
			}
			go func() {
				if err := staticServer.Serve(ln); err != nil {
					if !strings.Contains(err.Error(), "use of closed network connection") {
						cfg.PrintError("Couldn't listen to http: ", err)
					}
					return
				}
			}()
			app.Defer(func() {
				// Since we didn't use ListenAndServe, call
				// ln.Close() instead of staticServer.Close()
				ln.Close()
			})

			cfg.PublishedPorts[httpPort] = &config.Port{
				Src:      scfg.Port,
				To:       httpPort,
				Mode:     config.PublicPublishedMode,
				Protocol: config.AnyProtocol,
			}
		}
	}

	if len(cfg.PublishedPorts) == 0 && len(cfg.Binds) == 0 {
		fmt.Println()
		fmt.Println("ERROR: Can't run publish without any arguments!")
		fmt.Println(" HINT: Try 'diode publish -public 8080:80' to publish a local port")
		fmt.Println(" HINT: Check our docs to learn more about publishing ports: https://diode.io/docs/getting-started.html")
		fmt.Println(" HINT: Or run 'diode --help' to see all commands")
		os.Exit(2)
	}

	err = app.Start()
	if err != nil {
		return
	}
	if len(cfg.PublishedPorts) > 0 {
		cfg.PrintInfo("")
		name := cfg.ClientAddr.HexString()
		if cfg.ClientName != "" {
			name = cfg.ClientName
		}
		app.clientManager.GetPool().SetPublishedPorts(cfg.PublishedPorts)
		for _, port := range cfg.PublishedPorts {
			if port.To == httpPort {
				if port.Mode == config.PublicPublishedMode {
					cfg.PrintLabel("HTTP Gateway Enabled", fmt.Sprintf("http://%s.diode.link/", name))
				}
				break
			}
		}
		cfg.PrintLabel("Port      <name>", "<extern>     <mode>    <protocol>     <allowlist>")
		for _, port := range cfg.PublishedPorts {
			addrs := make([]string, 0, len(port.Allowlist))
			for addr := range port.Allowlist {
				addrs = append(addrs, addr.HexString())
			}
			host := net.JoinHostPort(port.SrcHost, strconv.Itoa(port.Src))
			cfg.PrintLabel(fmt.Sprintf("Port %12s", host), fmt.Sprintf("%8d  %10s       %s        %s", port.To, config.ModeName(port.Mode), config.ProtocolName(port.Protocol), strings.Join(addrs, ",")))
		}
	}

	if cfg.EnableAPIServer {
		configAPIServer := NewConfigAPIServer(cfg)
		configAPIServer.ListenAndServe()
		app.SetConfigAPIServer(configAPIServer)
	}
	socksCfg := rpc.Config{
		Addr:            cfg.SocksServerAddr(),
		FleetAddr:       cfg.FleetAddr,
		Blocklists:      cfg.Blocklists,
		Allowlists:      cfg.Allowlists,
		EnableProxy:     true,
		ProxyServerAddr: cfg.ProxyServerAddr(),
		Fallback:        cfg.SocksFallback,
	}
	socksServer, err := rpc.NewSocksServer(socksCfg, app.clientManager)
	if err != nil {
		return err
	}
	if cfg.EnableSocksServer {
		app.SetSocksServer(socksServer)
		if err = socksServer.Start(); err != nil {
			cfg.Logger.Error(err.Error())
			return
		}
	}
	if len(cfg.Binds) > 0 {
		socksServer.SetBinds(cfg.Binds)
		cfg.PrintInfo("")
		cfg.PrintLabel("Bind      <name>", "<mode>     <remote>")
		for _, bind := range cfg.Binds {
			cfg.PrintLabel(fmt.Sprintf("Port      %5d", bind.LocalPort), fmt.Sprintf("%5s     %11s:%d", config.ProtocolName(bind.Protocol), bind.To, bind.ToPort))
		}
	}
	for {
		app.Wait()
		if !app.Closed() {
			// Restart to publish utill user send sigint to client
			var client *rpc.Client
			for {
				client = app.WaitForFirstClient(true)
				if client != nil {
					break
				}
				cfg.Logger.Info("Could not connect to network trying again in 5 seconds")
				// TODO: backoff?
				time.Sleep(5 * time.Second)
			}
		} else {
			return
		}
	}
}
