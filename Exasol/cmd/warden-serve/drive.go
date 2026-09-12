package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"sync/atomic"
	"time"

	"mcp-warden/sandbox/pool"
	"mcp-warden/sandbox/runtime"
)

// driver replays a file of JSON-RPC requests against the confined pool on
// a loop, so a monitoring session has traffic to observe without a human
// driving curl.
//
// It exists because behavioural analysis of an idle server tells you
// almost nothing: most detectors compare a request against its peers, and
// a server that has served nothing has no peers to compare. Driving known
// traffic is also the only honest way to establish what a server's normal
// looks like before deciding that something is abnormal.
type driver struct {
	pool     *pool.Pool
	requests []driveRequest
	rate     float64
	timeout  time.Duration
	seq      atomic.Int64
	sent     atomic.Int64
	failed   atomic.Int64
}

type driveRequest struct {
	method string
	tool   string
	body   map[string]any
}

// loadRequests reads newline-delimited JSON-RPC requests. Blank lines and
// lines starting with # are skipped so a request file can be commented.
func loadRequests(path string) ([]driveRequest, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var out []driveRequest
	for i, line := range strings.Split(string(raw), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		var body map[string]any
		if err := json.Unmarshal([]byte(line), &body); err != nil {
			return nil, fmt.Errorf("%s line %d: %w", path, i+1, err)
		}
		if _, ok := body["jsonrpc"]; !ok {
			body["jsonrpc"] = "2.0"
		}
		req := driveRequest{body: body}
		if m, ok := body["method"].(string); ok {
			req.method = m
			req.tool = m
		}
		if params, ok := body["params"].(map[string]any); ok {
			if n, ok := params["name"].(string); ok {
				req.tool = n
			}
		}
		out = append(out, req)
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("%s contains no requests", path)
	}
	return out, nil
}

// run drives requests until ctx is cancelled.
func (d *driver) run(ctx context.Context) {
	interval := time.Second
	if d.rate > 0 {
		interval = time.Duration(float64(time.Second) / d.rate)
	}
	if interval < time.Millisecond {
		interval = time.Millisecond
	}
	t := time.NewTicker(interval)
	defer t.Stop()

	i := 0
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		req := d.requests[i%len(d.requests)]
		i++

		// Every send gets a fresh id. Reusing one would make the
		// runtime's id-matching pair a response with the wrong request
		// the moment two are ever in flight.
		n := d.seq.Add(1)
		body := make(map[string]any, len(req.body)+1)
		for k, v := range req.body {
			body[k] = v
		}
		if _, isNotification := body["id"]; !isNotification || body["method"] != "notifications/initialized" {
			body["id"] = n
		}
		payload, err := json.Marshal(body)
		if err != nil {
			d.failed.Add(1)
			continue
		}

		reqCtx, cancel := context.WithTimeout(ctx, d.timeout)
		_, err = d.pool.Do(reqCtx, runtime.ExecRequest{
			RequestID: fmt.Sprintf("drive_%06d", n),
			ToolName:  req.tool,
			Payload:   payload,
			Timeout:   d.timeout,
		})
		cancel()
		d.sent.Add(1)
		if err != nil {
			d.failed.Add(1)
		}
	}
}
