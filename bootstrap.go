package main

import (
	"fmt"
	"net/http"
	"net/url"
	"sync"
	"time"

	"v2rayN-win11/internal/bootproxy"
)

// 登录引导：官网接口经本地代理（内核）连不上时（例如国内还没有可用节点），临时在
// 127.0.0.1 随机端口起一个只给本程序官网 HTTP 客户端用的引导代理（internal/bootproxy，
// 经内置的「登录引导」节点出站，节点只放行 *.kncloud.top:443）。不改内核 / TUN / 系统代理，
// 不需要管理员权限。登录、刷新账户、同步订阅流程结束（最后一个 bootSession 释放）就关掉。

type bootState struct {
	mu    sync.Mutex
	p     *bootproxy.Proxy
	users int // 进行中的登录 / 刷新流程数
}

// startBootProxy 可在测试里替换。
var startBootProxy = func() (*bootproxy.Proxy, error) { return bootproxy.Start(bootproxy.Options{}) }

// bootSession 标记一个可能用到引导代理的流程；返回的函数在流程结束时调用（defer），
// 最后一个流程结束时关闭引导代理。
func (a *App) bootSession() func() {
	a.boot.mu.Lock()
	a.boot.users++
	a.boot.mu.Unlock()
	var once sync.Once
	return func() {
		once.Do(func() {
			a.boot.mu.Lock()
			defer a.boot.mu.Unlock()
			a.boot.users--
			if a.boot.users <= 0 {
				a.boot.users = 0
				if a.boot.p != nil {
					a.boot.p.Close()
					a.boot.p = nil
				}
			}
		})
	}
}

// bootPort 引导代理正在运行时的本地端口，否则 0。
func (a *App) bootPort() int {
	a.boot.mu.Lock()
	defer a.boot.mu.Unlock()
	if a.boot.p == nil || a.boot.p.Closed() {
		a.boot.p = nil
		return 0
	}
	return a.boot.p.Port()
}

// bootClient 启动（或复用）引导代理，返回只经它出站的官网 HTTP 客户端。
func (a *App) bootClient() (*http.Client, error) {
	a.boot.mu.Lock()
	if a.boot.p == nil || a.boot.p.Closed() {
		p, err := startBootProxy()
		if err != nil {
			a.boot.mu.Unlock()
			return nil, &panelNetError{fmt.Errorf("登录引导不可用：%v", err)}
		}
		a.boot.p = p
		a.addLogInternal("info", "官网连接失败，已临时启用登录引导（仅用于登录与拉取订阅）")
	}
	pu, _ := url.Parse(a.boot.p.URL())
	a.boot.mu.Unlock()
	return &http.Client{Timeout: panelRequestTimeout, Transport: &http.Transport{
		Proxy:                 http.ProxyURL(pu),
		TLSHandshakeTimeout:   15 * time.Second,
		ResponseHeaderTimeout: 30 * time.Second,
		DisableKeepAlives:     true,
	}}, nil
}
