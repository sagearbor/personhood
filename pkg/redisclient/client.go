// Package redisclient is a minimal, dependency-free Redis client (RESP2
// protocol over net.Conn) supporting exactly the commands the personhood
// session/token stores need: PING, AUTH, SELECT, SET (with PX), GET, DEL.
//
// Hand-rolled deliberately: every vendor integration elsewhere in this repo
// (SendGrid, Twilio, Persona, Plaid, Stripe) is a dependency-free net/http
// client rather than an SDK, and every method module's go.mod requires
// nothing beyond pkg/types. Pulling in github.com/redis/go-redis (and its
// transitive dependencies) into every module that wants Redis-backed
// storage would break that pattern for comparatively little benefit — the
// command surface these stores need is tiny.
//
// Each call opens and closes its own TCP connection. That is simple, safe
// under -race, and adequate for the request volumes these stores see
// (magic-link/OTP issuance and session lookups, not a hot data path); a
// connection pool would be a future optimization, not a correctness
// requirement.
package redisclient

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// ErrNotFound-equivalent: callers distinguish "key missing" via the bool
// return of Get rather than a sentinel error, so no ErrNotFound is exported.

// ReplyType classifies a parsed RESP2 reply. Only the subset of types the
// commands in this package can produce is represented.
type ReplyType int

const (
	ReplyStatus ReplyType = iota
	ReplyInteger
	ReplyBulk
	ReplyNil
)

// Reply is a parsed RESP2 server reply.
type Reply struct {
	Type ReplyType
	Str  string // status text, or the bulk string payload
	Int  int64
}

// Client is a minimal Redis client. Construct with New or ParseURL.
type Client struct {
	addr         string
	password     string
	db           int
	dialTimeout  time.Duration
	readTimeout  time.Duration
	writeTimeout time.Duration
}

// Option configures a Client constructed via New.
type Option func(*Client)

// WithPassword sets the password sent via AUTH on every new connection.
func WithPassword(password string) Option {
	return func(c *Client) { c.password = password }
}

// WithDB selects a logical database (SELECT) on every new connection.
// Redis's default database (0) needs no SELECT call.
func WithDB(db int) Option {
	return func(c *Client) { c.db = db }
}

// WithTimeouts overrides the default 5s dial/read/write timeouts. A zero
// duration disables that particular timeout.
func WithTimeouts(dial, read, write time.Duration) Option {
	return func(c *Client) {
		c.dialTimeout, c.readTimeout, c.writeTimeout = dial, read, write
	}
}

// New constructs a Client for the given "host:port" address.
func New(addr string, opts ...Option) *Client {
	c := &Client{
		addr:         addr,
		dialTimeout:  5 * time.Second,
		readTimeout:  5 * time.Second,
		writeTimeout: 5 * time.Second,
	}
	for _, opt := range opts {
		opt(c)
	}
	return c
}

// ParseURL parses the standard REDIS_URL convention,
// "redis://[:password@]host:port[/db]", into a Client. A bare "host:port"
// with no "redis://" scheme is also accepted, for convenience.
//
// "rediss://" (TLS) is deliberately not supported — this client speaks
// plain RESP2 over an unencrypted net.Conn — and is rejected with a clear
// error rather than silently connecting without TLS.
func ParseURL(raw string) (*Client, error) {
	if strings.TrimSpace(raw) == "" {
		return nil, errors.New("redisclient: empty URL")
	}
	if !strings.Contains(raw, "://") {
		return New(raw), nil
	}
	u, err := url.Parse(raw)
	if err != nil {
		return nil, fmt.Errorf("redisclient: parse %q: %w", raw, err)
	}
	if u.Scheme != "redis" {
		return nil, fmt.Errorf("redisclient: unsupported scheme %q (want redis://; rediss:// TLS is not implemented)", u.Scheme)
	}
	if u.Host == "" {
		return nil, fmt.Errorf("redisclient: %q has no host", raw)
	}

	var opts []Option
	if u.User != nil {
		if pw, ok := u.User.Password(); ok && pw != "" {
			opts = append(opts, WithPassword(pw))
		} else if pw := u.User.Username(); pw != "" {
			// redis://:password@host — the password-only form some clients
			// emit — parses as Username() with no Password(); accept it too.
			opts = append(opts, WithPassword(pw))
		}
	}
	if path := strings.TrimPrefix(u.Path, "/"); path != "" {
		db, err := strconv.Atoi(path)
		if err != nil {
			return nil, fmt.Errorf("redisclient: %q has a non-numeric database path %q", raw, path)
		}
		opts = append(opts, WithDB(db))
	}
	return New(u.Host, opts...), nil
}

func (c *Client) dial(ctx context.Context) (net.Conn, error) {
	d := net.Dialer{Timeout: c.dialTimeout}
	conn, err := d.DialContext(ctx, "tcp", c.addr)
	if err != nil {
		return nil, fmt.Errorf("redisclient: dial %s: %w", c.addr, err)
	}
	if c.password != "" {
		if _, err := doOnConn(conn, c.writeTimeout, c.readTimeout, "AUTH", c.password); err != nil {
			conn.Close()
			return nil, fmt.Errorf("redisclient: AUTH: %w", err)
		}
	}
	if c.db != 0 {
		if _, err := doOnConn(conn, c.writeTimeout, c.readTimeout, "SELECT", strconv.Itoa(c.db)); err != nil {
			conn.Close()
			return nil, fmt.Errorf("redisclient: SELECT %d: %w", c.db, err)
		}
	}
	return conn, nil
}

// Do sends a single RESP2 command and returns its parsed reply.
func (c *Client) Do(ctx context.Context, args ...string) (Reply, error) {
	conn, err := c.dial(ctx)
	if err != nil {
		return Reply{}, err
	}
	defer conn.Close()
	return doOnConn(conn, c.writeTimeout, c.readTimeout, args...)
}

// Ping verifies connectivity (and AUTH/SELECT, if configured).
func (c *Client) Ping(ctx context.Context) error {
	reply, err := c.Do(ctx, "PING")
	if err != nil {
		return err
	}
	if reply.Str != "PONG" {
		return fmt.Errorf("redisclient: unexpected PING reply %q", reply.Str)
	}
	return nil
}

// Set stores value under key, replacing any previous entry (and its TTL).
// If ttl > 0, the key expires after ttl (millisecond precision via Redis's
// PX option); ttl <= 0 means no expiry.
func (c *Client) Set(ctx context.Context, key string, value []byte, ttl time.Duration) error {
	args := []string{"SET", key, string(value)}
	if ttl > 0 {
		args = append(args, "PX", strconv.FormatInt(ttl.Milliseconds(), 10))
	}
	_, err := c.Do(ctx, args...)
	return err
}

// Get returns the value stored at key. found is false (with a nil error) if
// the key does not exist — a normal cache miss, not a failure.
func (c *Client) Get(ctx context.Context, key string) (value []byte, found bool, err error) {
	reply, err := c.Do(ctx, "GET", key)
	if err != nil {
		return nil, false, err
	}
	if reply.Type == ReplyNil {
		return nil, false, nil
	}
	return []byte(reply.Str), true, nil
}

// Del removes key. Idempotent: deleting a missing key is not an error.
func (c *Client) Del(ctx context.Context, key string) error {
	_, err := c.Do(ctx, "DEL", key)
	return err
}

func doOnConn(conn net.Conn, writeTimeout, readTimeout time.Duration, args ...string) (Reply, error) {
	if writeTimeout > 0 {
		_ = conn.SetWriteDeadline(time.Now().Add(writeTimeout))
	}
	if _, err := conn.Write(encodeCommand(args)); err != nil {
		return Reply{}, fmt.Errorf("redisclient: write: %w", err)
	}
	if readTimeout > 0 {
		_ = conn.SetReadDeadline(time.Now().Add(readTimeout))
	}
	reply, err := readReply(bufio.NewReader(conn))
	if err != nil {
		return Reply{}, err
	}
	return reply, nil
}

func encodeCommand(args []string) []byte {
	var b strings.Builder
	fmt.Fprintf(&b, "*%d\r\n", len(args))
	for _, a := range args {
		fmt.Fprintf(&b, "$%d\r\n%s\r\n", len(a), a)
	}
	return []byte(b.String())
}

func readReply(r *bufio.Reader) (Reply, error) {
	line, err := readLine(r)
	if err != nil {
		return Reply{}, fmt.Errorf("redisclient: read reply: %w", err)
	}
	if line == "" {
		return Reply{}, errors.New("redisclient: empty reply line")
	}
	switch line[0] {
	case '+':
		return Reply{Type: ReplyStatus, Str: line[1:]}, nil
	case '-':
		return Reply{}, fmt.Errorf("redisclient: server error: %s", line[1:])
	case ':':
		n, err := strconv.ParseInt(line[1:], 10, 64)
		if err != nil {
			return Reply{}, fmt.Errorf("redisclient: bad integer reply %q: %w", line, err)
		}
		return Reply{Type: ReplyInteger, Int: n}, nil
	case '$':
		n, err := strconv.Atoi(line[1:])
		if err != nil {
			return Reply{}, fmt.Errorf("redisclient: bad bulk length %q: %w", line, err)
		}
		if n < 0 {
			return Reply{Type: ReplyNil}, nil
		}
		buf := make([]byte, n+2) // +2 for the trailing \r\n
		if _, err := io.ReadFull(r, buf); err != nil {
			return Reply{}, fmt.Errorf("redisclient: read bulk payload: %w", err)
		}
		return Reply{Type: ReplyBulk, Str: string(buf[:n])}, nil
	default:
		return Reply{}, fmt.Errorf("redisclient: unsupported reply type %q (only +/-/:/$ are used by this client's command set)", line[0])
	}
}

func readLine(r *bufio.Reader) (string, error) {
	line, err := r.ReadString('\n')
	if err != nil {
		return "", err
	}
	return strings.TrimRight(line, "\r\n"), nil
}
