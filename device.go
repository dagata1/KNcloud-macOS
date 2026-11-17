package main

import (
	"crypto/rand"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	goruntime "runtime"
	"strings"
	"sync"

	"github.com/wailsapp/wails/v2/pkg/runtime"
)

// 设备登记（面板「设备管理」）：请求官网账户接口与账户订阅时带上本机的设备标识，
// 面板据此登记 / 限制设备，并可能为本设备下发独立的订阅地址（device_subscribe_url）。
//
//	X-KN-Device-Id       随机 UUID v4，首次使用时生成并保存在配置目录（device-id 文件），
//	                     不由任何硬件序列号派生
//	X-KN-Device-Name     默认取计算机名（面板里可改名，客户端不提供改名界面）
//	X-KN-Platform        windows | macos
//	X-KN-Client-Version  程序版本（appVersion）
//
// 只发给官网账户接口与账户订阅；用户手动添加的第三方订阅不带这些头。
const (
	hdrDeviceID      = "X-KN-Device-Id"
	hdrDeviceName    = "X-KN-Device-Name"
	hdrPlatform      = "X-KN-Platform"
	hdrClientVersion = "X-KN-Client-Version"
)

const deviceIDFile = "device-id"

var (
	deviceIDOnce sync.Once
	deviceIDVal  string
)

var uuidV4Re = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)

// newUUIDv4 生成随机 UUID v4（crypto/rand）。
func newUUIDv4() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return ""
	}
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}

// loadOrCreateDeviceID 读取 dir/device-id；不存在或内容无效时生成新的并写回。
// 写入失败时仍返回本次生成的 ID（本次运行内保持不变）。
func loadOrCreateDeviceID(dir string) string {
	path := ""
	if dir != "" {
		path = filepath.Join(dir, deviceIDFile)
		if data, err := os.ReadFile(path); err == nil {
			if id := strings.ToLower(strings.TrimSpace(string(data))); uuidV4Re.MatchString(id) {
				return id
			}
		}
	}
	id := newUUIDv4()
	if path != "" && id != "" {
		_ = os.WriteFile(path, []byte(id+"\n"), 0600)
	}
	return id
}

// deviceID 本机设备 ID（进程内缓存）。
func deviceID() string {
	deviceIDOnce.Do(func() {
		dir, _ := appConfigDir()
		deviceIDVal = loadOrCreateDeviceID(dir)
	})
	return deviceIDVal
}

// deviceName 默认设备名：计算机名。
func deviceName() string {
	h, err := os.Hostname()
	if err != nil {
		return ""
	}
	return strings.TrimSpace(h)
}

func devicePlatform() string {
	switch goruntime.GOOS {
	case "darwin":
		return "macos"
	case "windows":
		return "windows"
	}
	return goruntime.GOOS
}

// deviceHeaders 本机设备登记头（官网账户接口、账户订阅使用）。
func deviceHeaders() map[string]string {
	h := map[string]string{
		hdrPlatform:      devicePlatform(),
		hdrClientVersion: appVersion,
	}
	if id := deviceID(); id != "" {
		h[hdrDeviceID] = id
	}
	if n := headerSafe(deviceName()); n != "" {
		h[hdrDeviceName] = n
	}
	return h
}

// headerSafe 去掉控制字符（主机名理论上不会有，防御性处理）；非 ASCII 按原样发送（Go 按字节写出）。
func headerSafe(s string) string {
	return strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return -1
		}
		return r
	}, s)
}

func setDeviceHeaders(req *http.Request) {
	for k, v := range deviceHeaders() {
		req.Header.Set(k, v)
	}
}

// deviceSubInvalidStatus 设备订阅地址失效的状态码：面板对无效 / 已移除的订阅令牌返回 403/404/410（401 一并视为失效）。
func deviceSubInvalidStatus(code int) bool {
	switch code {
	case http.StatusUnauthorized, http.StatusForbidden, http.StatusNotFound, http.StatusGone:
		return true
	}
	return false
}

// accountErrToast 托盘 / 自动更新失败时给界面的提示：面板拒绝的原话、设备被移除、或通用「更新失败：…」。
func accountErrToast(err error) string {
	var pe *panelMsgError
	switch {
	case errors.As(err, &pe):
		return pe.msg
	case errors.Is(err, errDeviceRemoved):
		return "此设备已在面板中移除，请重新登录"
	}
	return "更新失败：" + err.Error()
}

// notifyDeviceRemoved 后台（自动更新 / 托盘）发现设备订阅失效：界面刷新回到登录页并提示。
func (a *App) notifyDeviceRemoved(err error) {
	if !errors.Is(err, errDeviceRemoved) {
		return
	}
	if ctx := a.appCtx(); ctx != nil {
		runtime.EventsEmit(ctx, "kncloud:refresh")
	}
	a.emitToast(accountErrToast(err), "error")
}
