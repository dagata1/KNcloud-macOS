//go:build windows

package main

import "syscall"

// systemLangIsChinese Windows 界面语言（GetUserDefaultUILanguage）主语言为中文时返回 true。
func systemLangIsChinese() bool {
	proc := syscall.NewLazyDLL("kernel32.dll").NewProc("GetUserDefaultUILanguage")
	if proc.Find() != nil {
		return true
	}
	r, _, _ := proc.Call()
	return uint16(r)&0x3ff == 0x04 // LANG_CHINESE
}
