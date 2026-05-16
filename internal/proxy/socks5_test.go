package proxy

import (
	"bufio"
	"bytes"
	"testing"
)

func TestSOCKS5NegotiateDomain(t *testing.T) {
	host := "example.com"
	stream := []byte{socks5Version, 0x01, socks5NoAuth} // greeting: one method, no auth
	req := []byte{socks5Version, socks5CmdConn, 0x00, socks5ATYPHost, byte(len(host))}
	req = append(req, []byte(host)...)
	req = append(req, 0x01, 0xbb) // port 443
	stream = append(stream, req...)

	var out bytes.Buffer
	target, err := socks5Negotiate(bufio.NewReader(bytes.NewReader(stream)), &out)
	if err != nil {
		t.Fatalf("socks5Negotiate: %v", err)
	}
	if target != "example.com:443" {
		t.Errorf("target = %q, want example.com:443", target)
	}

	reply := out.Bytes()
	if len(reply) != 2+10 {
		t.Fatalf("reply length = %d, want 12", len(reply))
	}
	if reply[0] != socks5Version || reply[1] != socks5NoAuth {
		t.Errorf("method selection = % x, want 05 00", reply[:2])
	}
	if reply[3] != socks5ReplyOK {
		t.Errorf("connect reply status = 0x%02x, want 0x00", reply[3])
	}
}

func TestSOCKS5NegotiateIPv4(t *testing.T) {
	stream := []byte{socks5Version, 0x01, socks5NoAuth}
	stream = append(stream, socks5Version, socks5CmdConn, 0x00, socks5ATYPv4,
		203, 0, 113, 9, 0x01, 0xbb)

	var out bytes.Buffer
	target, err := socks5Negotiate(bufio.NewReader(bytes.NewReader(stream)), &out)
	if err != nil {
		t.Fatalf("socks5Negotiate: %v", err)
	}
	if target != "203.0.113.9:443" {
		t.Errorf("target = %q, want 203.0.113.9:443", target)
	}
}

func TestSOCKS5RejectsBindCommand(t *testing.T) {
	stream := []byte{socks5Version, 0x01, socks5NoAuth}
	stream = append(stream, socks5Version, 0x02 /* BIND */, 0x00, socks5ATYPv4,
		0, 0, 0, 0, 0, 0)

	var out bytes.Buffer
	if _, err := socks5Negotiate(bufio.NewReader(bytes.NewReader(stream)), &out); err == nil {
		t.Error("expected error for unsupported BIND command")
	}
}
