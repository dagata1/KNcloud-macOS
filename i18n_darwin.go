//go:build darwin

package main

import (
	"os/exec"
	"strings"
)

// systemLangIsChinese macOS 首选语言（AppleLanguages 第一项）为中文时返回 true。
func systemLangIsChinese() bool {
	out, err := exec.Command("/usr/bin/defaults", "read", "-g", "AppleLanguages").Output()
	if err != nil {
		return true
	}
	for _, line := range strings.Split(string(out), "\n") {
		s := strings.Trim(strings.TrimSpace(line), `",()`)
		if s == "" {
			continue
		}
		return strings.HasPrefix(strings.ToLower(s), "zh")
	}
	return true
}
