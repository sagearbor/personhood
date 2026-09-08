package email

import (
	"bufio"
	"context"
	"encoding/base64"
	"fmt"
	"net"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

// fakeSMTPServer is a minimal SMTP server good enough to exercise SMTPSender
// end to end: EHLO/AUTH PLAIN/MAIL/RCPT/DATA/QUIT over plaintext (no
// STARTTLS — SMTPSender only attempts STARTTLS when the server advertises
// it, and this fake never does, matching how a plaintext local relay such as
// MailHog/smtp4dev behaves on a trusted network).
type fakeSMTPServer struct {
	listener net.Listener

	mu         sync.Mutex
	messages   []capturedSMTPMessage
	rejectRcpt bool // reject every RCPT TO with 550
	closed     bool
}

type capturedSMTPMessage struct {
	from    string
	to      string
	authRaw string // decoded AUTH PLAIN payload, empty if no AUTH
	data    string
}

func newFakeSMTPServer(t *testing.T) *fakeSMTPServer {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	s := &fakeSMTPServer{listener: ln}
	go s.serve()
	t.Cleanup(func() {
		s.mu.Lock()
		s.closed = true
		s.mu.Unlock()
		_ = ln.Close()
	})
	return s
}

func (s *fakeSMTPServer) hostPort() (string, string) {
	addr := s.listener.Addr().(*net.TCPAddr)
	return "127.0.0.1", strconv.Itoa(addr.Port)
}

func (s *fakeSMTPServer) serve() {
	for {
		conn, err := s.listener.Accept()
		if err != nil {
			return
		}
		go s.handle(conn)
	}
}

func (s *fakeSMTPServer) handle(conn net.Conn) {
	defer conn.Close()
	r := bufio.NewReader(conn)
	w := bufio.NewWriter(conn)
	writeLine := func(line string) {
		w.WriteString(line + "\r\n")
		w.Flush()
	}

	writeLine("220 fake.smtp.test ESMTP ready")

	var cur capturedSMTPMessage
	for {
		line, err := r.ReadString('\n')
		if err != nil {
			return
		}
		line = strings.TrimRight(line, "\r\n")
		upper := strings.ToUpper(line)

		switch {
		case strings.HasPrefix(upper, "EHLO"), strings.HasPrefix(upper, "HELO"):
			writeLine("250-fake.smtp.test greets you")
			writeLine("250-AUTH PLAIN")
			writeLine("250 8BITMIME")
		case strings.HasPrefix(upper, "AUTH PLAIN"):
			fields := strings.SplitN(line, " ", 3)
			if len(fields) == 3 {
				if decoded, err := base64.StdEncoding.DecodeString(fields[2]); err == nil {
					cur.authRaw = string(decoded)
				}
			}
			writeLine("235 2.7.0 Authentication successful")
		case strings.HasPrefix(upper, "MAIL FROM:"):
			cur.from = line[len("MAIL FROM:"):]
			writeLine("250 2.1.0 OK")
		case strings.HasPrefix(upper, "RCPT TO:"):
			s.mu.Lock()
			reject := s.rejectRcpt
			s.mu.Unlock()
			if reject {
				writeLine("550 5.1.1 No such user")
				continue
			}
			cur.to = line[len("RCPT TO:"):]
			writeLine("250 2.1.5 OK")
		case upper == "DATA":
			writeLine("354 End data with <CR><LF>.<CR><LF>")
			var body strings.Builder
			for {
				dl, err := r.ReadString('\n')
				if err != nil {
					return
				}
				if dl == ".\r\n" || dl == ".\n" {
					break
				}
				body.WriteString(dl)
			}
			cur.data = body.String()
			s.mu.Lock()
			s.messages = append(s.messages, cur)
			s.mu.Unlock()
			cur = capturedSMTPMessage{}
			writeLine("250 2.0.0 OK: queued")
		case upper == "QUIT":
			writeLine("221 2.0.0 Bye")
			return
		case upper == "RSET":
			cur = capturedSMTPMessage{}
			writeLine("250 2.0.0 OK")
		default:
			writeLine("500 5.5.2 Command not recognized")
		}
	}
}

func (s *fakeSMTPServer) lastMessage() (capturedSMTPMessage, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.messages) == 0 {
		return capturedSMTPMessage{}, false
	}
	return s.messages[len(s.messages)-1], true
}

func TestSMTPSender_Send_Success_WithAuth(t *testing.T) {
	srv := newFakeSMTPServer(t)
	host, port := srv.hostPort()

	sender, err := NewSMTPSender(host, port, "alice", "app-password", "noreply@example.com")
	if err != nil {
		t.Fatalf("NewSMTPSender: %v", err)
	}
	sender.DialTimeout = 5 * time.Second

	link := "https://issuer.example/v1/methods/email/verify?session=s&token=t"
	if err := sender.Send(context.Background(), "bob@example.com", "Confirm your email", link); err != nil {
		t.Fatalf("Send: %v", err)
	}

	msg, ok := srv.lastMessage()
	if !ok {
		t.Fatal("server never received a completed message")
	}
	if !strings.Contains(msg.from, "noreply@example.com") {
		t.Errorf("MAIL FROM mismatch: %q", msg.from)
	}
	if !strings.Contains(msg.to, "bob@example.com") {
		t.Errorf("RCPT TO mismatch: %q", msg.to)
	}
	if !strings.Contains(msg.data, link) {
		t.Errorf("DATA missing magic link: %q", msg.data)
	}
	if !strings.Contains(msg.data, "multipart/alternative") {
		t.Errorf("DATA missing multipart header: %q", msg.data)
	}
	wantAuth := "\x00alice\x00app-password"
	if msg.authRaw != wantAuth {
		t.Errorf("AUTH PLAIN payload = %q, want %q", msg.authRaw, wantAuth)
	}
}

func TestSMTPSender_Send_Success_NoAuth(t *testing.T) {
	srv := newFakeSMTPServer(t)
	host, port := srv.hostPort()

	// No user/pass: the sender must not attempt AUTH at all.
	sender, err := NewSMTPSender(host, port, "", "", "noreply@example.com")
	if err != nil {
		t.Fatalf("NewSMTPSender: %v", err)
	}
	sender.DialTimeout = 5 * time.Second

	if err := sender.Send(context.Background(), "carol@example.com", "subj", "https://issuer.example/verify?token=t2"); err != nil {
		t.Fatalf("Send: %v", err)
	}
	msg, ok := srv.lastMessage()
	if !ok {
		t.Fatal("server never received a completed message")
	}
	if msg.authRaw != "" {
		t.Errorf("expected no AUTH, got payload %q", msg.authRaw)
	}
	if !strings.Contains(msg.to, "carol@example.com") {
		t.Errorf("RCPT TO mismatch: %q", msg.to)
	}
}

func TestSMTPSender_Send_RcptRejected(t *testing.T) {
	srv := newFakeSMTPServer(t)
	srv.mu.Lock()
	srv.rejectRcpt = true
	srv.mu.Unlock()
	host, port := srv.hostPort()

	sender, err := NewSMTPSender(host, port, "", "", "noreply@example.com")
	if err != nil {
		t.Fatalf("NewSMTPSender: %v", err)
	}
	sender.DialTimeout = 5 * time.Second

	err = sender.Send(context.Background(), "nobody@example.com", "subj", "https://issuer.example/verify")
	if err == nil {
		t.Fatal("expected error when RCPT TO is rejected")
	}
	if !strings.Contains(err.Error(), "rcpt") {
		t.Errorf("error should mention rcpt: %v", err)
	}
}

func TestSMTPSender_Send_DialFailure(t *testing.T) {
	// A closed listener's address should refuse connections immediately.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	addr := ln.Addr().(*net.TCPAddr)
	_ = ln.Close()

	sender, err := NewSMTPSender("127.0.0.1", fmt.Sprintf("%d", addr.Port), "", "", "noreply@example.com")
	if err != nil {
		t.Fatalf("NewSMTPSender: %v", err)
	}
	sender.DialTimeout = 3 * time.Second

	if err := sender.Send(context.Background(), "x@example.com", "s", "https://x"); err == nil {
		t.Fatal("expected dial error against a closed port")
	}
}

func TestNewSMTPSender_ValidatesRequired(t *testing.T) {
	if _, err := NewSMTPSender("", "587", "", "", "from@x.com"); err == nil {
		t.Error("expected error on empty host")
	}
	if _, err := NewSMTPSender("smtp.example.com", "587", "", "", ""); err == nil {
		t.Error("expected error on empty From address")
	}
}

func TestNewSMTPSender_DefaultsPort(t *testing.T) {
	s, err := NewSMTPSender("smtp.example.com", "", "", "", "from@x.com")
	if err != nil {
		t.Fatalf("NewSMTPSender: %v", err)
	}
	if s.Port != "587" {
		t.Errorf("expected default port 587, got %q", s.Port)
	}
}

func TestSMTPSenderFromEnv(t *testing.T) {
	t.Setenv("SMTP_HOST", "smtp.example.com")
	t.Setenv("SMTP_PORT", "2525")
	t.Setenv("SMTP_USER", "u")
	t.Setenv("SMTP_PASS", "p")
	t.Setenv("SMTP_FROM", "from@example.com")

	sender := smtpSenderFromEnv()
	s, ok := sender.(*SMTPSender)
	if !ok {
		t.Fatalf("expected *SMTPSender, got %T", sender)
	}
	if s.Host != "smtp.example.com" || s.Port != "2525" || s.User != "u" || s.Pass != "p" || s.From != "from@example.com" {
		t.Errorf("unexpected sender fields: %+v", s)
	}
}

func TestSMTPSenderFromEnv_MissingHost(t *testing.T) {
	t.Setenv("SMTP_HOST", "")
	t.Setenv("SMTP_FROM", "from@example.com")
	if sender := smtpSenderFromEnv(); sender != nil {
		t.Errorf("expected nil sender when SMTP_HOST unset, got %v", sender)
	}
}

func TestNewSenderFromEnv_PrefersSMTPOverLogWhenConfigured(t *testing.T) {
	// This test only exercises the non-sendgrid build (the default); the
	// sendgrid-tagged build has its own precedence tests in
	// sendgrid_sender_test.go.
	t.Setenv("SENDGRID_API_KEY", "")
	t.Setenv("SMTP_HOST", "smtp.example.com")
	t.Setenv("SMTP_FROM", "from@example.com")
	t.Setenv("SMTP_PORT", "")
	t.Setenv("SMTP_USER", "")
	t.Setenv("SMTP_PASS", "")

	sender := NewSenderFromEnv()
	if _, ok := sender.(*SMTPSender); !ok {
		t.Fatalf("expected *SMTPSender from NewSenderFromEnv, got %T", sender)
	}
}

func TestNewSenderFromEnv_FallsBackToLogSender(t *testing.T) {
	t.Setenv("SENDGRID_API_KEY", "")
	t.Setenv("SMTP_HOST", "")
	t.Setenv("SMTP_FROM", "")

	sender := NewSenderFromEnv()
	if _, ok := sender.(*LogSender); !ok {
		t.Fatalf("expected *LogSender, got %T", sender)
	}
}
