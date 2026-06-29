// agent.go: the signet agent — own-the-token, sign-on-request.
//
// signet is otherwise a one-shot CLI that opens the hardware on every call. That
// does not work when the workload that needs to attest cannot reach the hardware
// at all: a container has no pcscd socket and no path to the YubiKey, and mounting
// the token into the most exposed container is the wrong trade-off. The agent is
// the ssh-agent / SPIRE node-agent / HSM-proxy answer: one process owns the token
// and signs attestation nonces for socket clients on request.
//
// Two halves live here:
//
//   - the serve side (`signet agent --bind <socket>=<slot> ...`): one daemon owns
//     the single-access YubiKey and serves a Unix socket per binding. Each socket
//     is pinned to ONE slot at listen time; the slot is never taken from a request,
//     so a client on a socket can only ever sign with that socket's key — it cannot
//     impersonate another identity. All hardware access is serialised through one
//     mutex because the token is single-access. The agent exposes exactly two ops,
//     pubkey and sign; it never generates or overwrites a key (enrolment stays a
//     deliberate host operation).
//
//   - the client side (agentSigner, selected by `--agent <socket>` on sign / enrol
//     / auth): a Signer that forwards PublicKeyDER and Sign over the socket instead
//     of opening local hardware. Because attestation is resolve-by-public-key, the
//     broker neither knows nor cares that the signature came via the agent.
//
// Security model: the private key never leaves the YubiKey and the device never
// leaves the agent. A compromised client can ask for a signature over a nonce, but
// the broker's challenge nonces are single-use (replay-dead) and the slot binding
// stops it attesting as anything but itself; it cannot extract a key.
package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"
)

// agentConnTimeout bounds a single request/response exchange on the serve side;
// agentDialTimeout bounds the client's dial-plus-exchange. Both are generous
// enough for a YubiKey touch-free signature, which is sub-second.
const (
	agentConnTimeout = 15 * time.Second
	agentDialTimeout = 15 * time.Second
	agentSocketMode  = 0o660
)

// agentRequest and agentResponse are the newline-delimited JSON wire protocol.
// A request names an op (and, for sign, the message); the slot is NEVER carried
// on the wire — it is fixed by the socket the client connected to.
type agentRequest struct {
	Op      string `json:"op"`                // "pubkey" | "sign"
	Message string `json:"message,omitempty"` // sign only
}

type agentResponse struct {
	PublicKeyDER string `json:"public_key_der,omitempty"`
	SignatureB64 string `json:"signature_b64,omitempty"`
	Error        string `json:"error,omitempty"`
}

// bindList collects repeatable --bind <socket>=<slot> values.
type bindList []string

func (b *bindList) String() string { return strings.Join(*b, ",") }

func (b *bindList) Set(v string) error {
	*b = append(*b, v)
	return nil
}

// parseBind splits a "<socket>=<slot>" binding. The separator is the last '='
// so socket paths are unconstrained (slot names never contain '=').
func parseBind(s string) (socket, slot string, err error) {
	i := strings.LastIndex(s, "=")
	if i < 0 {
		return "", "", fmt.Errorf("invalid --bind %q; want <socket>=<slot> (e.g. /run/signet/bd.sock=9c)", s)
	}
	socket, slot = s[:i], s[i+1:]
	if socket == "" || slot == "" {
		return "", "", fmt.Errorf("invalid --bind %q; want <socket>=<slot> (e.g. /run/signet/bd.sock=9c)", s)
	}
	return socket, slot, nil
}

// cmdAgent runs the agent: one listener per binding, all sharing a single
// hardware mutex, until a termination signal arrives.
func cmdAgent(backend string, binds bindList) error {
	if len(binds) == 0 {
		return fmt.Errorf("signet agent: at least one --bind <socket>=<slot> is required")
	}

	var hw sync.Mutex // serialises every hardware access (the token is single-access)
	var listeners []net.Listener
	var sockets []string
	var wg sync.WaitGroup

	// Tear down anything already opened if a later binding fails to start.
	cleanup := func() {
		for _, ln := range listeners {
			ln.Close()
		}
		for _, s := range sockets {
			os.Remove(s)
		}
	}

	for _, raw := range binds {
		socket, slot, err := parseBind(raw)
		if err != nil {
			cleanup()
			return err
		}
		signer, err := newSigner(backend, slot, "")
		if err != nil {
			cleanup()
			return fmt.Errorf("bind %s: %w", socket, err)
		}
		ln, err := listenUnix(socket)
		if err != nil {
			cleanup()
			return err
		}
		listeners = append(listeners, ln)
		sockets = append(sockets, socket)
		wg.Add(1)
		go func(ln net.Listener, signer Signer) {
			defer wg.Done()
			serveAgent(ln, signer, &hw)
		}(ln, signer)
		fmt.Fprintf(os.Stderr, "signet agent: serving %s (backend %s, slot %s)\n", socket, backend, slot)
	}

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	<-sigCh
	fmt.Fprintln(os.Stderr, "signet agent: shutting down")

	for _, ln := range listeners {
		ln.Close() // unblocks the Accept loops
	}
	wg.Wait()
	for _, s := range sockets {
		os.Remove(s)
	}
	return nil
}

// listenUnix removes a stale socket from a previous run, binds it, and tightens
// its mode so only the owner and a shared group can reach it.
func listenUnix(socket string) (net.Listener, error) {
	if err := os.Remove(socket); err != nil && !os.IsNotExist(err) {
		return nil, fmt.Errorf("remove stale socket %s: %w", socket, err)
	}
	ln, err := net.Listen("unix", socket)
	if err != nil {
		return nil, fmt.Errorf("listen %s: %w", socket, err)
	}
	if err := os.Chmod(socket, agentSocketMode); err != nil {
		ln.Close()
		os.Remove(socket)
		return nil, fmt.Errorf("chmod %s: %w", socket, err)
	}
	return ln, nil
}

// serveAgent accepts connections on ln and handles each with signer, which is
// pinned to this listener's slot. Returns when ln is closed (shutdown).
func serveAgent(ln net.Listener, signer Signer, hw *sync.Mutex) {
	for {
		conn, err := ln.Accept()
		if err != nil {
			return // listener closed on shutdown
		}
		go handleAgentConn(conn, signer, hw)
	}
}

// handleAgentConn reads one request, performs the bound op under the hardware
// mutex, and writes one response. The slot is the listener's, never the client's.
func handleAgentConn(conn net.Conn, signer Signer, hw *sync.Mutex) {
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(agentConnTimeout))

	var req agentRequest
	if err := json.NewDecoder(bufio.NewReader(conn)).Decode(&req); err != nil {
		writeAgentResponse(conn, agentResponse{Error: "invalid request: " + err.Error()})
		return
	}

	var resp agentResponse
	switch req.Op {
	case "pubkey":
		hw.Lock()
		pub, err := signer.PublicKeyDER()
		hw.Unlock()
		if err != nil {
			resp.Error = err.Error()
		} else {
			resp.PublicKeyDER = pub
		}
	case "sign":
		if req.Message == "" {
			resp.Error = "sign requires a non-empty message"
			break
		}
		hw.Lock()
		sig, err := signer.Sign(req.Message)
		hw.Unlock()
		if err != nil {
			resp.Error = err.Error()
		} else {
			resp.SignatureB64 = sig
		}
	default:
		resp.Error = fmt.Sprintf("unknown op %q (want pubkey | sign)", req.Op)
	}
	writeAgentResponse(conn, resp)
}

func writeAgentResponse(conn net.Conn, resp agentResponse) {
	b, err := json.Marshal(resp)
	if err != nil {
		return
	}
	_, _ = conn.Write(append(b, '\n'))
}

// agentSigner is the client half: a Signer that forwards to an agent socket.
type agentSigner struct {
	socket  string
	timeout time.Duration
}

func newAgentSigner(socket string) *agentSigner {
	return &agentSigner{socket: socket, timeout: agentDialTimeout}
}

// Enrol via the agent does NOT generate a key (the agent has no such op);
// it returns the slot's existing public key, the way `signet enrol` reports a
// key it did not need to create. Key generation stays a host operation.
func (a *agentSigner) Enrol(userPresence bool) (string, error) {
	return a.PublicKeyDER()
}

func (a *agentSigner) PublicKeyDER() (string, error) {
	resp, err := a.call(agentRequest{Op: "pubkey"})
	if err != nil {
		return "", err
	}
	if resp.PublicKeyDER == "" {
		return "", fmt.Errorf("signet agent: empty public key in response")
	}
	return resp.PublicKeyDER, nil
}

func (a *agentSigner) Sign(message string) (string, error) {
	resp, err := a.call(agentRequest{Op: "sign", Message: message})
	if err != nil {
		return "", err
	}
	if resp.SignatureB64 == "" {
		return "", fmt.Errorf("signet agent: empty signature in response")
	}
	return resp.SignatureB64, nil
}

func (a *agentSigner) call(req agentRequest) (agentResponse, error) {
	conn, err := net.DialTimeout("unix", a.socket, a.timeout)
	if err != nil {
		return agentResponse{}, fmt.Errorf("signet agent: dial %s: %w", a.socket, err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(a.timeout))

	b, err := json.Marshal(req)
	if err != nil {
		return agentResponse{}, err
	}
	if _, err := conn.Write(append(b, '\n')); err != nil {
		return agentResponse{}, fmt.Errorf("signet agent: write %s: %w", a.socket, err)
	}

	var resp agentResponse
	if err := json.NewDecoder(bufio.NewReader(conn)).Decode(&resp); err != nil {
		return agentResponse{}, fmt.Errorf("signet agent: read %s: %w", a.socket, err)
	}
	if resp.Error != "" {
		return agentResponse{}, fmt.Errorf("signet agent: %s", resp.Error)
	}
	return resp, nil
}
