package bootproxy

// 登录引导节点（官网直连不通时，应用自己的官网接口请求临时经它出站）。
// 这是唯一一处写引导节点参数的地方；发版时可用 -ldflags "-X v2rayN-win11/internal/bootproxy.Password=..." 覆盖。
// 引导账号只在面板「登录引导」权限组里，节点套了「仅允许」路由：只能访问 *.kncloud.top:443，
// 不能用来正常上网，所以写进客户端是可以接受的。
var (
	// Host 引导节点域名（只有 AAAA 记录）。
	Host = "sea1.kncloud.top"
	// FallbackIP DNS 解析失败 / 连不上时直接用的 IPv6。
	FallbackIP = "2603:c022:8017:5aee:f8da:150d:efc:6f96"
	// Port 引导节点端口。
	Port = "3456"
	// Method 加密方式（目前只实现 chacha20-ietf-poly1305）。
	Method = "chacha20-ietf-poly1305"
	// Password 引导账号的 SS 密码（面板 uuid）。为空则引导功能关闭。
	Password = "ecd6b75b-b7ff-45f7-941e-b585bdb5b8e4"
)

// Enabled 是否配置了引导节点。
func Enabled() bool { return Host != "" && Port != "" && Password != "" }
