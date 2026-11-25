package main

import (
	"fmt"
	"strings"
)

// CopyNodeShareLink 生成选中节点的分享链接并写入系统剪贴板
func (a *App) CopyNodeShareLink(id string) (bool, error) {
	a.mu.RLock()
	var node NodeItem
	found := false
	for i := range a.nodes {
		if a.nodes[i].ID == id {
			node = a.nodes[i]
			found = true
			break
		}
	}
	a.mu.RUnlock()
	if !found {
		return false, fmt.Errorf("node not found")
	}
	link, err := BuildShareLink(node)
	if err != nil {
		return false, err
	}
	if err := setClipboardText(link); err != nil {
		return false, err
	}
	a.addLogInternal("info", fmt.Sprintf("Node share link copied to clipboard: [%s] %s", node.Protocol, node.Name))
	return true, nil
}

// CopyNodesShareLinks 把多个节点的分享链接（按节点列表顺序，一行一个）写入系统剪贴板，返回复制的数量。
// 无法生成链接的节点会跳过；一个都生成不了时报错。
func (a *App) CopyNodesShareLinks(ids []string) (int, error) {
	if len(ids) == 0 {
		return 0, fmt.Errorf("no node selected")
	}
	want := make(map[string]bool, len(ids))
	for _, id := range ids {
		want[id] = true
	}
	a.mu.RLock()
	var picked []NodeItem
	for i := range a.nodes {
		if want[a.nodes[i].ID] {
			picked = append(picked, a.nodes[i])
		}
	}
	a.mu.RUnlock()
	if len(picked) == 0 {
		return 0, fmt.Errorf("node not found")
	}
	links := make([]string, 0, len(picked))
	var lastErr error
	for _, n := range picked {
		link, err := BuildShareLink(n)
		if err != nil {
			lastErr = err
			continue
		}
		links = append(links, link)
	}
	if len(links) == 0 {
		return 0, lastErr
	}
	if err := setClipboardText(strings.Join(links, "\n")); err != nil {
		return 0, err
	}
	a.addLogInternal("info", fmt.Sprintf("Copied %d node share link(s) to clipboard", len(links)))
	return len(links), nil
}

// ImportNodesFromClipboard 读取剪贴板并导入其中可识别的节点分享链接，返回导入数量。
// 剪贴板内容不是分享链接时返回 0（前端静默处理，不打扰用户）。
func (a *App) ImportNodesFromClipboard() (int, error) {
	text, err := clipboardText()
	if err != nil {
		return 0, err
	}
	nodes, skipped := ParseShareLinksReport(text)
	if msg := skippedLinksLog(skipped); msg != "" {
		a.addLogInternal("warn", msg)
	}
	if len(nodes) == 0 {
		return 0, nil
	}

	a.mu.Lock()
	defer a.mu.Unlock()
	for i := range nodes {
		nodes[i].ID = newNodeID()
		if nodes[i].Group == "" {
			nodes[i].Group = "Custom"
		}
		a.nodes = append(a.nodes, nodes[i])
	}
	a.addLogInternal("info", fmt.Sprintf("Imported %d node(s) from clipboard", len(nodes)))
	a.savePersisted()
	tray.requestRebuild()
	return len(nodes), nil
}
