package bootproxy

import (
	"crypto/cipher"
	"crypto/md5"
	"crypto/rand"
	"crypto/sha1"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"

	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/hkdf"
)

// 最小的 Shadowsocks AEAD（chacha20-ietf-poly1305）TCP 客户端，只用于登录引导。
// 协议：salt(32) + 若干 chunk，每个 chunk = Seal(len 2 字节) + Seal(payload ≤ 0x3FFF)，
// 子密钥 = HKDF-SHA1(EVP_BytesToKey(password), salt, "ss-subkey")，nonce 为 12 字节小端计数器。

const (
	keySize     = 32
	saltSize    = 32
	maxPayload  = 0x3FFF
	tagOverhead = 16
)

// evpBytesToKey OpenSSL EVP_BytesToKey(MD5, 无盐, 1 轮)，与 shadowsocks 各实现一致。
func evpBytesToKey(password string, keyLen int) []byte {
	var out, prev []byte
	for len(out) < keyLen {
		h := md5.New()
		h.Write(prev)
		h.Write([]byte(password))
		prev = h.Sum(nil)
		out = append(out, prev...)
	}
	return out[:keyLen]
}

func subkeyAEAD(key, salt []byte) (cipher.AEAD, error) {
	sub := make([]byte, keySize)
	if _, err := io.ReadFull(hkdf.New(sha1.New, key, salt, []byte("ss-subkey")), sub); err != nil {
		return nil, err
	}
	return chacha20poly1305.New(sub)
}

func incNonce(n []byte) {
	for i := range n {
		n[i]++
		if n[i] != 0 {
			return
		}
	}
}

// ssConn 把明文读写包装成 SS AEAD 流。
type ssConn struct {
	net.Conn
	key []byte

	enc      cipher.AEAD
	encNonce []byte

	dec      cipher.AEAD
	decNonce []byte
	rbuf     []byte // 已解密未读出的数据
}

func newSSConn(c net.Conn, password string) *ssConn {
	return &ssConn{Conn: c, key: evpBytesToKey(password, keySize)}
}

func (c *ssConn) Write(p []byte) (int, error) {
	var out []byte
	if c.enc == nil {
		salt := make([]byte, saltSize)
		if _, err := rand.Read(salt); err != nil {
			return 0, err
		}
		a, err := subkeyAEAD(c.key, salt)
		if err != nil {
			return 0, err
		}
		c.enc, c.encNonce = a, make([]byte, a.NonceSize())
		out = append(out, salt...)
	}
	n := 0
	for len(p) > 0 {
		chunk := p
		if len(chunk) > maxPayload {
			chunk = chunk[:maxPayload]
		}
		var l [2]byte
		binary.BigEndian.PutUint16(l[:], uint16(len(chunk)))
		out = c.enc.Seal(out, c.encNonce, l[:], nil)
		incNonce(c.encNonce)
		out = c.enc.Seal(out, c.encNonce, chunk, nil)
		incNonce(c.encNonce)
		p = p[len(chunk):]
		n += len(chunk)
	}
	if _, err := c.Conn.Write(out); err != nil {
		return 0, err
	}
	return n, nil
}

func (c *ssConn) Read(p []byte) (int, error) {
	if len(c.rbuf) == 0 {
		if c.dec == nil {
			salt := make([]byte, saltSize)
			if _, err := io.ReadFull(c.Conn, salt); err != nil {
				return 0, err
			}
			a, err := subkeyAEAD(c.key, salt)
			if err != nil {
				return 0, err
			}
			c.dec, c.decNonce = a, make([]byte, a.NonceSize())
		}
		buf := make([]byte, 2+tagOverhead)
		if _, err := io.ReadFull(c.Conn, buf); err != nil {
			return 0, err
		}
		l, err := c.dec.Open(buf[:0], c.decNonce, buf, nil)
		if err != nil {
			return 0, errors.New("shadowsocks: bad length chunk (wrong password?)")
		}
		incNonce(c.decNonce)
		size := int(binary.BigEndian.Uint16(l)) & maxPayload
		buf = make([]byte, size+tagOverhead)
		if _, err := io.ReadFull(c.Conn, buf); err != nil {
			return 0, err
		}
		data, err := c.dec.Open(buf[:0], c.decNonce, buf, nil)
		if err != nil {
			return 0, errors.New("shadowsocks: bad payload chunk")
		}
		incNonce(c.decNonce)
		c.rbuf = data
	}
	n := copy(p, c.rbuf)
	c.rbuf = c.rbuf[n:]
	return n, nil
}

// socksAddr SOCKS5 风格目标地址（域名交给节点解析，节点的「仅允许」按域名放行）。
func socksAddr(hostport string) ([]byte, error) {
	host, port, err := net.SplitHostPort(hostport)
	if err != nil {
		return nil, err
	}
	pn, err := strconv.Atoi(port)
	if err != nil || pn <= 0 || pn > 65535 {
		return nil, fmt.Errorf("bad port %q", port)
	}
	var b []byte
	if ip := net.ParseIP(host); ip != nil {
		if v4 := ip.To4(); v4 != nil {
			b = append([]byte{1}, v4...)
		} else {
			b = append([]byte{4}, ip.To16()...)
		}
	} else {
		if len(host) == 0 || len(host) > 255 {
			return nil, fmt.Errorf("bad host %q", host)
		}
		b = append([]byte{3, byte(len(host))}, host...)
	}
	return binary.BigEndian.AppendUint16(b, uint16(pn)), nil
}
