package api

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/gorilla/websocket"
	"obsidianwatch/management/internal/store"
)

func handleGuacamole(db *store.DB, registry *TunnelRegistry, logger *slog.Logger) http.HandlerFunc {
	guacdAddr := "guacd:4822"

	return func(w http.ResponseWriter, r *http.Request) {
		// Parse token — Guacamole.WebSocketTunnel appends ?<uuid> to the URL.
		token := ""
		for _, part := range strings.Split(r.URL.RawQuery, "&") {
			if strings.HasPrefix(part, "token=") {
				v := strings.TrimPrefix(part, "token=")
				if idx := strings.Index(v, "?"); idx != -1 {
					v = v[:idx]
				}
				token = strings.TrimSpace(v)
				break
			}
		}
		if token == "" {
			http.Error(w, "token required", 400)
			return
		}

		session, err := db.GetLRSession(r.Context(), token)
		if err != nil || session.Status == "closed" || session.Status == "failed" {
			http.Error(w, "invalid or expired session", 400)
			return
		}

		tunnel, ok := registry.Get(session.AgentID)
		if !ok {
			http.Error(w, "agent tunnel not connected", 503)
			return
		}

		username, _, rdpPassword, err := db.GetLRCredential(r.Context(), session.AgentID)
		if err != nil {
			http.Error(w, "no credentials for agent", 503)
			return
		}

		// Open local TCP listener — guacd connects here as the RDP target
		listener, err := net.Listen("tcp", "0.0.0.0:0")
		if err != nil {
			logger.Error("lr: guac: listener failed", "err", err)
			http.Error(w, "internal error", 500)
			return
		}
		defer listener.Close()
		localPort := listener.Addr().(*net.TCPAddr).Port
		logger.Info("lr: guac: rdp listener opened", "port", localPort)

		// Register agent data channel
		dataCh := make(chan []byte, 512)
		tunnel.mu.Lock()
		tunnel.sessions[token] = dataCh
		tunnel.mu.Unlock()
		defer func() {
			tunnel.mu.Lock()
			delete(tunnel.sessions, token)
			tunnel.mu.Unlock()
		}()

		// Tell agent to start forwarding
		tunnel.sendJSON(wireMsg{Type: "forward_port", Token: token})

		// Accept guacd's RDP connection in background (guacd connects after handshake)
		rdpConnCh := make(chan net.Conn, 1)
		rdpErrCh  := make(chan error, 1)
		go func() {
			listener.(*net.TCPListener).SetDeadline(time.Now().Add(20 * time.Second))
			conn, err := listener.Accept()
			if err != nil {
				rdpErrCh <- err
				return
			}
			rdpConnCh <- conn
		}()

		// Upgrade browser WebSocket
		upgrader := websocket.Upgrader{
			CheckOrigin:  func(r *http.Request) bool { return true },
			Subprotocols: []string{"guacamole"},
		}
		browserWS, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			logger.Warn("lr: guac: browser upgrade failed", "err", err)
			return
		}
		defer browserWS.Close()

		db.UpdateLRSessionStatus(r.Context(), token, "active")
		logger.Info("lr: guac: session started", "agent", session.AgentID, "protocol", session.Protocol, "token", token[:8]+"...")

		// Connect to guacd
		guacdConn, err := net.DialTimeout("tcp", guacdAddr, 10*time.Second)
		if err != nil {
			logger.Error("lr: guac: cannot connect to guacd", "err", err)
			browserWS.WriteMessage(websocket.TextMessage, []byte("10.error,15.guacd unavailable,1.0;"))
			return
		}
		defer guacdConn.Close()

		rdpPort := fmt.Sprintf("%d", localPort)
		if err := guacdHandshake(guacdConn, session.Protocol, "mgmt-api", rdpPort, username, rdpPassword, logger); err != nil {
			logger.Error("lr: guac: handshake failed", "err", err)
			browserWS.WriteMessage(websocket.TextMessage, []byte("10.error,16.handshake failed,1.0;"))
			return
		}
		logger.Info("lr: guac: handshake done, waiting for guacd rdp connect", "port", localPort)

		// Wait for guacd to connect to our RDP listener
		var rdpConn net.Conn
		select {
		case rdpConn = <-rdpConnCh:
			logger.Info("lr: guac: guacd connected for rdp", "port", localPort)
		case err := <-rdpErrCh:
			logger.Error("lr: guac: guacd did not connect", "err", err)
			browserWS.WriteMessage(websocket.TextMessage, []byte("10.error,20.rdp connect timeout,1.0;"))
			return
		}
		defer rdpConn.Close()

		// Pipe agent tunnel ↔ guacd RDP socket
		// dataCh carries json.RawMessage (base64-encoded []byte from agent's json.Marshal)
		// Unmarshal each payload to get raw bytes before writing to rdpConn
		go func() {
			for payload := range dataCh {
				var raw []byte
				if err := json.Unmarshal(payload, &raw); err == nil {
					rdpConn.Write(raw)
				}
			}
		}()
		go func() {
			buf := make([]byte, 32*1024)
			for {
				n, err := rdpConn.Read(buf)
				if n > 0 {
					payload, _ := json.Marshal(buf[:n])
					tunnel.sendJSON(wireMsg{
						Type:    "data",
						Token:   token,
						Payload: json.RawMessage(payload),
					})
				}
				if err != nil {
					return
				}
			}
		}()

		// Proxy browser WS ↔ guacd Guacamole protocol
		// IMPORTANT: Guacamole.js requires complete instructions (ending in ';') per WS message.
		// We must buffer TCP reads from guacd and send one complete instruction at a time.
		done := make(chan struct{}, 2)
		go func() {
			defer func() { done <- struct{}{} }()
			for {
				_, msg, err := browserWS.ReadMessage()
				if err != nil {
					return
				}
				if _, err := guacdConn.Write(msg); err != nil {
					return
				}
			}
		}()
		go func() {
			defer func() { done <- struct{}{} }()
			reader := bufio.NewReaderSize(guacdConn, 256*1024)
			var count int
			for {
				instruction, err := readGuacInstruction(reader)
				if len(instruction) > 0 {
					count++
					// Log first 5 instructions and every 100th to diagnose display
					if count <= 5 || count%100 == 0 {
						preview := string(instruction)
						if len(preview) > 80 {
							preview = preview[:80] + "..."
						}
						logger.Info("lr: guac: →browser", "n", count, "instr", preview)
					}
					if werr := browserWS.WriteMessage(websocket.TextMessage, instruction); werr != nil {
						logger.Warn("lr: guac: browser write failed", "err", werr, "after", count)
						return
					}
				}
				if err != nil {
					logger.Warn("lr: guac: guacd read error", "err", err, "after", count)
					return
				}
			}
		}()

		<-done
		db.UpdateLRSessionStatus(r.Context(), token, "closed")
		logger.Info("lr: guac: session ended", "token", token[:8]+"...")
	}
}

// guacdHandshake performs the Guacamole protocol handshake.
// Critically: we parse guacd's args list and fill EXACTLY those args by name.
// readGuacInstruction reads exactly one complete Guacamole instruction from a bufio.Reader.
// Guacamole protocol: LENGTH.ELEMENT,LENGTH.ELEMENT,...;
// We parse lengths explicitly so we never split on ';' inside base64 image data.
func readGuacInstruction(r *bufio.Reader) ([]byte, error) {
	var buf []byte
	first := true
	for {
		// Read the length prefix (digits before '.')
		lenStr, err := r.ReadString('.')
		if err != nil {
			return buf, err
		}
		buf = append(buf, []byte(lenStr)...)
		// Parse the length
		lenStr = lenStr[:len(lenStr)-1] // strip '.'
		var elemLen int
		for _, c := range lenStr {
			if c < '0' || c > '9' {
				return buf, fmt.Errorf("non-numeric in length: %q", lenStr)
			}
			elemLen = elemLen*10 + int(c-'0')
		}
		// Read exactly elemLen bytes (the element value)
		elem := make([]byte, elemLen)
		if _, err := io.ReadFull(r, elem); err != nil {
			return buf, err
		}
		buf = append(buf, elem...)
		// Read the terminator: ',' (more elements) or ';' (end of instruction)
		term, err := r.ReadByte()
		if err != nil {
			return buf, err
		}
		buf = append(buf, term)
		if term == ';' {
			// Check if this was the opcode (first element) — if instruction is just opcode+semicolon it's complete
			_ = first
			return buf, nil
		}
		first = false
		// term == ',' → read next element
		// But wait — after the element, we need the next length prefix
		// which starts with digits then '.'. Loop continues.
		_ = first
	}
}

func guacdHandshake(conn net.Conn, protocol, host, port, username, password string, logger *slog.Logger) error {
	conn.SetDeadline(time.Now().Add(15 * time.Second))
	defer conn.SetDeadline(time.Time{})

	reader := bufio.NewReader(conn)

	// 1. Select protocol
	if _, err := fmt.Fprintf(conn, guacInstr("select", protocol)); err != nil {
		return fmt.Errorf("select: %w", err)
	}

	// 2. Send client capabilities
	if _, err := fmt.Fprintf(conn, guacInstr("size", "1280", "800", "96")); err != nil {
		return fmt.Errorf("size: %w", err)
	}
	if _, err := fmt.Fprintf(conn, guacInstr("audio")); err != nil {
		return fmt.Errorf("audio: %w", err)
	}
	if _, err := fmt.Fprintf(conn, guacInstr("video")); err != nil {
		return fmt.Errorf("video: %w", err)
	}
	if _, err := fmt.Fprintf(conn, guacInstr("image", "image/png", "image/jpeg", "image/webp")); err != nil {
		return fmt.Errorf("image: %w", err)
	}
	if _, err := fmt.Fprintf(conn, guacInstr("timezone", "UTC")); err != nil {
		return fmt.Errorf("timezone: %w", err)
	}

	// 3. Read args from guacd — format: "4.args,N.argname,N.argname,...;"
	argsLine, err := reader.ReadString(';')
	if err != nil {
		return fmt.Errorf("read args: %w", err)
	}
	logger.Info("lr: guac: args from guacd", "args", argsLine)

	argNames := parseGuacArgs(argsLine)
	logger.Info("lr: guac: parsed arg names", "count", len(argNames), "names", argNames)

	// 4. Build connect values keyed by arg name
	// These are the RDP params guacd 1.6 advertises
	rdpParams := map[string]string{
		"hostname":                    host,
		"port":                        port,
		"username":                    username,
		"password":                    password,
		"domain":                      "",
		"security":                    "rdp",
		"ignore-cert":                 "true",
		"disable-auth":                "false",
		"remote-app":                  "",
		"remote-app-dir":              "",
		"remote-app-args":             "",
		"client-name":                 "ObsidianWatch",
		"width":                       "1280",
		"height":                      "800",
		"dpi":                         "96",
		"color-depth":                 "24",
		"cursor":                      "local",
		"swap-red-blue":               "",
		"dest-host":                   "",
		"dest-port":                   "",
		"recording-path":              "",
		"recording-name":              "",
		"recording-exclude-output":    "",
		"recording-exclude-mouse":     "",
		"recording-include-keys":      "",
		"create-recording-path":       "",
		"enable-sftp":                 "false",
		"sftp-hostname":               "",
		"sftp-host-key":               "",
		"sftp-port":                   "",
		"sftp-username":               "",
		"sftp-password":               "",
		"sftp-private-key":            "",
		"sftp-passphrase":             "",
		"sftp-root-directory":         "",
		"sftp-directory":              "",
		"sftp-server-alive-interval":  "",
		"sftp-disable-download":       "",
		"sftp-disable-upload":         "",
		"enable-audio":                "true",
		"static-channels":             "",
		"clipboard-encoding":          "",
		"disable-copy":                "",
		"disable-paste":               "",
		"normalize-clipboard":         "",
		"server-layout":               "",
		"timezone":                    "UTC",
		"console":                     "true",
		"console-audio":               "",
		"resize-method":               "display-update",
		"enable-wallpaper":            "true",
		"enable-theming":              "true",
		"enable-font-smoothing":       "true",
		"enable-full-window-drag":     "true",
		"enable-desktop-composition":  "true",
		"enable-menu-animations":      "true",
		"disable-bitmap-caching":      "",
		"disable-offscreen-caching":   "",
		"disable-glyph-caching":       "",
		"preconnection-id":            "",
		"preconnection-blob":          "",
		"load-balance-info":           "",
		"gateway-hostname":            "",
		"gateway-port":                "",
		"gateway-domain":              "",
		"gateway-username":            "",
		"gateway-password":            "",
		"force-lossless":              "",
		"read-only":                   "",
		"wol-send-packet":             "",
		"wol-mac-addr":                "",
		"wol-broadcast-addr":          "",
		"wol-udp-port":                "",
		"wol-wait-time":               "",
	}

	// Fill args in EXACT order guacd gave us
	connectVals := make([]string, len(argNames))
	for i, name := range argNames {
		connectVals[i] = rdpParams[name] // empty string if unknown arg
	}

	// 5. Send connect
	if _, err := fmt.Fprintf(conn, guacInstr("connect", connectVals...)); err != nil {
		return fmt.Errorf("connect: %w", err)
	}

	// 6. Read ready
	readyLine, err := reader.ReadString(';')
	if err != nil {
		return fmt.Errorf("read ready: %w", err)
	}
	logger.Info("lr: guac: ready response", "line", readyLine)
	if !strings.Contains(readyLine, "ready") {
		return fmt.Errorf("expected ready, got: %s", readyLine)
	}

	return nil
}

// parseGuacArgs parses a Guacamole args instruction and returns the arg names.
// Format: "4.args,N.name1,N.name2,...;"
func parseGuacArgs(line string) []string {
	line = strings.TrimSuffix(strings.TrimSpace(line), ";")
	parts := strings.Split(line, ",")
	var names []string
	for i, p := range parts {
		if i == 0 {
			continue // skip "4.args"
		}
		// Each part is "N.value"
		dot := strings.Index(p, ".")
		if dot < 0 {
			continue
		}
		n, err := strconv.Atoi(p[:dot])
		if err != nil || dot+1+n > len(p) {
			continue
		}
		names = append(names, p[dot+1:dot+1+n])
	}
	return names
}

// guacInstr formats a Guacamole protocol instruction.
func guacInstr(opcode string, args ...string) string {
	parts := make([]string, 0, len(args)+1)
	parts = append(parts, fmt.Sprintf("%d.%s", len(opcode), opcode))
	for _, a := range args {
		parts = append(parts, fmt.Sprintf("%d.%s", len(a), a))
	}
	return strings.Join(parts, ",") + ";"
}
