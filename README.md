# CCZUVPNProto

## 简介

CCZUVPNProto 是常州大学 WebVPN 协议的 Swift 客户端库，提供了从 SSO 登录、代理授权到 TLS 隧道数据收发的一体化实现。

本项目是 Rust 版本 cczuni 的 VPN 协议层 Swift 重写版本，专为 Apple 平台优化，可直接用于 iOS/macOS/watchOS/tvOS 项目。

## 特性

✅ SSO 登录流程封装 - 自动处理重定向、Cookie 与 clientInfo 解析
✅ WebVPN 可用性检查 - 快速判断账号是否可用 WebVPN
✅ 代理授权协议实现 - 完整构建授权包并解析服务端授权响应
✅ TLS 连接封装 - 基于 Network.framework 的异步收发
✅ 心跳机制 - 自动心跳与轮询节流，保持连接活性
✅ 数据包收发 - 支持原始包和 TCP 封装包发送
✅ 异步并发 - 基于 Swift Concurrency (async/await + actor)
✅ 类型安全 - 明确的配置模型、错误模型与服务端信息模型
✅ 跨平台 - 支持 iOS、macOS、watchOS、tvOS

## 系统要求

- iOS 15.0+
- macOS 12.0+
- watchOS 8.0+
- tvOS 15.0+
- Swift 6.0+
- Xcode 15.0+

## 安装

### Swift Package Manager

在 Package.swift 中添加依赖：

```swift
dependencies: [
    .package(url: "https://github.com/CCZU-OSSA/cczu-vpn-proto.git", from: "1.0.0")
]
```

然后在 target 中添加：

```swift
targets: [
    .target(
        name: "YourTarget",
        dependencies: [
            .product(name: "CCZUVPNProto", package: "cczu-vpn-proto")
        ]
    )
]
```

或在 Xcode 中：

1. File → Add Package Dependencies
2. 输入仓库 URL: https://github.com/CCZU-OSSA/cczu-vpn-proto.git
3. 选择版本并添加到项目

## 使用示例

### 基础使用

```swift
import Foundation
import CCZUVPNProto

let service = CCZUVPNService()

// 先检查 WebVPN 是否可用
let available = await service.webVPNAvailable()
guard available else {
    print("当前账号或环境不可用 WebVPN")
    return
}

// 启动服务（startService 返回 Bool）
let ok = await service.startService(user: "你的学号", password: "你的密码")
guard ok else {
    print("启动失败")
    return
}

print("服务启动成功")
```

### 发送与接收数据

```swift
import Foundation
import CCZUVPNProto

let service = CCZUVPNService()
try await service.start(user: "你的学号", password: "你的密码")

// 发送原始数据包
let sentRaw = await service.sendPacket(Data([0x01, 0x02, 0x03]))
print("原始包发送结果: \(sentRaw)")

// 发送 TCP 封装包
let sentTCP = await service.sendTCPPacket(Data([0x45, 0x00]))
print("TCP 包发送结果: \(sentTCP)")

// 手动发送心跳
let heartBeatSent = await service.sendHeartbeat()
print("心跳发送结果: \(heartBeatSent)")

// 接收指定长度数据（返回值为 [4字节长度前缀 + 包体]）
let frame = await service.receivePacket(size: 1500)
print("收到帧长度: \(frame.count)")
```

### 轮询收包

```swift
import Foundation
import CCZUVPNProto

let service = CCZUVPNService()
try await service.start(user: "你的学号", password: "你的密码")

service.startPollingPacket { size, packet in
    if size == 0 {
        // size=0 表示轮询过程出现错误，packet 内是错误字符串的 UTF-8 数据
        print("轮询错误: \(String(decoding: packet, as: UTF8.self))")
        return
    }

    print("收到数据包: \(size) bytes")
    // TODO: 将 packet 写入你的 TUN/TAP 设备
}

// 停止轮询
service.stopPollingPacket()
```

### 自定义配置

```swift
import Foundation
import CCZUVPNProto

let configuration = CCZUVPNConfiguration(
    ssoLoginURL: URL(string: "http://sso.cczu.edu.cn/sso/login")!,
    vpnRootURL: URL(string: "https://zmvpn.cczu.edu.cn")!,
    proxyHost: "zmvpn.cczu.edu.cn",
    proxyPort: 443,
    userAgent: "Mozilla/5.0 ...",
    skipTLSVerification: true
)

let service = CCZUVPNService(configuration: configuration)
try await service.start(user: "你的学号", password: "你的密码")

if let proxy = await service.proxyServer {
    print("虚拟地址: \(proxy.address)")
    print("子网掩码: \(proxy.mask)")
    print("网关: \(proxy.gateway)")
    print("DNS: \(proxy.dns)")
    print("WINS: \(proxy.wins)")
}
```

### 停止服务

```swift
import CCZUVPNProto

let stopped = await service.stopService()
print("服务是否成功停止: \(stopped)")
```

## API 文档

### 核心类型

### CCZUVPNService

VPN 服务入口，负责登录授权、隧道连接和数据收发。

```swift
let service = CCZUVPNService(configuration: CCZUVPNConfiguration = .init())

// WebVPN 可用性
await service.webVPNAvailable() -> Bool

// 启动（安全版，抛错）
try await service.start(user: String, password: String) -> Void

// 启动（便捷版，不抛错）
await service.startService(user: String, password: String) -> Bool

// 服务状态
await service.serviceAvailable() -> Bool

// 停止服务
await service.stopService() -> Bool

// 发送原始包
await service.sendPacket(Data) -> Bool

// 发送 TCP 封装包
await service.sendTCPPacket(Data) -> Bool

// 发送心跳
await service.sendHeartbeat() -> Bool

// 接收固定长度包体（返回带长度前缀的数据帧）
await service.receivePacket(size: Int) -> Data

// 启动/停止轮询收包
await service.startPollingPacket((_ size: UInt32, _ packet: Data) -> Void) -> Void
await service.stopPollingPacket() -> Void

// 授权后解析出的代理服务端信息
await service.proxyServer -> ProxyServer?
```

### CCZUVPNConfiguration

连接配置。

```swift
public struct CCZUVPNConfiguration {
    var ssoLoginURL: URL
    var vpnRootURL: URL
    var proxyHost: String
    var proxyPort: UInt16
    var userAgent: String
    var skipTLSVerification: Bool
}
```

### ProxyServer

授权成功后服务端返回的网络参数。

```swift
public struct ProxyServer {
    let address: String
    let mask: String
    let gateway: String
    var dns: String
    let wins: String
}
```

## 错误处理

```swift
do {
    try await service.start(user: "你的学号", password: "你的密码")
    // 处理成功
} catch CCZUVPNError.webVPNUnavailable {
    print("WebVPN 不可用")
} catch CCZUVPNError.authorizationFailed {
    print("代理授权失败")
} catch CCZUVPNError.transportDisconnected {
    print("TLS 连接已断开")
} catch CCZUVPNError.timeout {
    print("请求超时")
} catch CCZUVPNError.unsupportedStatus(let code) {
    print("HTTP 状态异常: \(code)")
} catch CCZUVPNError.malformedServerData(let reason) {
    print("服务端数据格式异常: \(reason)")
} catch {
    print("未知错误: \(error)")
}
```

### 常见错误及处理

| 错误类型 | 含义 | 处理建议 |
| --- | --- | --- |
| invalidResponse | 非法 HTTP 响应对象 | 检查网络环境和请求目标 |
| missingLocation | 重定向缺少 Location | 检查 SSO 流程是否变更 |
| missingClientInfo | 登录后未获得 clientInfo Cookie | 检查账号状态和 SSO 响应 |
| webVPNUnavailable | 当前账号不可用 WebVPN | 确认账号权限或登录方式 |
| authorizationFailed | VPN 代理授权失败 | 检查账号密码或服务端状态 |
| transportDisconnected | TLS 连接断开 | 检查网络稳定性并重连 |
| timeout | 收发超时 | 增加重试并检查网络延迟 |
| unsupportedStatus(code) | 接口返回了意外状态码 | 记录状态码并排查接口变更 |
| malformedServerData(reason) | 服务端返回结构异常 | 打印原始响应并更新解析逻辑 |

## 与 Rust 版本的区别

### 优势

✅ 类型安全：Swift 强类型系统提供更好的编译时检查
✅ 现代异步：基于 Swift Concurrency (async/await + actor)
✅ Apple 生态：可无缝接入 SwiftUI / Network.framework
✅ 内存安全：ARC 管理对象生命周期

### 功能对应

| Rust 版本概念 | Swift 版本对应 |
| --- | --- |
| 客户端服务入口 | CCZUVPNService |
| SSO + 规则获取 | SSOAuthClient（内部实现） |
| 协议包编码 | AuthorizationPacket / TCPPacket |
| TLS 隧道 | TLSProxyConnection（内部实现） |
| 共享状态 | actor 隔离 + Sendable |

## 注意事项

- 当前库仅实现 VPN 协议与隧道收发，不包含 TUN/TAP 设备创建逻辑。
- 默认 skipTLSVerification = true，与原实现保持兼容；生产环境建议按需开启证书校验。
- 使用选项中建议优先使用 start(user:password:) 获取明确错误信息，便于排障。

## 贡献

欢迎提交 Issue 和 Pull Request。

## 许可证

GNU Affero General Public License v3.0 (AGPL-3.0)

## 相关项目

- cczuni - Rust 版本
- CCZU-OSSA/cczu-vpn-proto - 参考协议实现

## 致谢

感谢 CCZU-OSSA 团队的开源贡献。
