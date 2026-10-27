//go:build !windows && !darwin

package main

import (
	"os"
	"strings"
)

func systemLangIsChinese() bool {
	for _, k := range []string{"LC_ALL", "LC_MESSAGES", "LANG"} {
		if v := os.Getenv(k); v != "" {
			return strings.HasPrefix(strings.ToLower(v), "zh")
		}
	}
	return true
}
