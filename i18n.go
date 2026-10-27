package main

import "sync/atomic"

// 界面语言（托盘 / 菜单栏菜单、原生对话框）。
//
// 偏好保存在 settings.language：system（跟随系统，默认）/ zh-CN / en。
// 前端（navigator.language）解析出实际生效语言后调用 SetUILanguage 通知这里；
// 在前端就绪之前（例如启动早期的原生对话框）按配置 + 系统界面语言推断。
// 后端返回给界面的错误 / 提示文本仍为中文，由前端 i18n.js 的 trMsg 在英文界面下翻译。

var uiLangEN atomic.Bool

// L 按当前生效语言在中文 / 英文文案之间二选一。
func L(zh, en string) string {
	if uiLangEN.Load() {
		return en
	}
	return zh
}

func validLanguage(l string) bool {
	return l == "system" || l == "zh-CN" || l == "en"
}

// applyLanguagePref 按持久化的偏好设置生效语言（system 时看系统界面语言）。
func applyLanguagePref(pref string) {
	switch pref {
	case "en":
		uiLangEN.Store(true)
	case "zh-CN":
		uiLangEN.Store(false)
	default:
		uiLangEN.Store(!systemLangIsChinese())
	}
}

// SetUILanguage 前端告知实际生效的界面语言（"zh-CN" / "en"），变化时重建托盘菜单。
func (a *App) SetUILanguage(lang string) {
	en := lang == "en"
	if uiLangEN.Swap(en) != en {
		tray.requestRebuild()
	}
}
