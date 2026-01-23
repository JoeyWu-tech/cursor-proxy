# FakeIP 模块优化技术规范

> 审查日期: 2026-01-23  
> 审查版本: v1.2.0  
> 触发条件: 用户反馈启用 FakeIP 后代理失效/崩溃

---

## 一、问题概述

### 1.1 用户反馈症状

- 启用 FakeIP (`fake_ip.enabled = true`) 后，部分场景下代理转发失效
- 关闭 FakeIP (`fake_ip.enabled = false`) 后恢复正常
- 日志显示 `SOCKS5: [1/3] 发送认证协商失败, WSA错误码=10057`
- 进程崩溃退出

### 1.2 日志证据

```
[错误] SOCKS5: [1/3] 发送认证协商失败, sock=5424, WSA错误码=10057
[错误] SOCKS5 握手失败, sock=5424, 目标=daily-cloudcode-pa.googleapis.com:443
[错误] GetQueuedCompletionStatusEx: ConnectEx 握手失败
```

**关键错误码**：WSA 10057 = `WSAENOTCONN` (Socket is not connected)

---

## 二、根因分析

### 2.1 问题根源

问题出在 `Hooks.cpp` 的 IOCP 完成事件处理逻辑：

**原代码缺陷**（`DetourGetQueuedCompletionStatusEx`，第 1605-1619 行）：

```cpp
if (result && lpCompletionPortEntries && ulNumEntriesRemoved && *ulNumEntriesRemoved > 0) {
    for (ULONG i = 0; i < *ulNumEntriesRemoved; i++) {
        LPOVERLAPPED ovl = lpCompletionPortEntries[i].lpOverlapped;
        if (ovl) {
            // ❌ 问题 1：未检查 Internal (NTSTATUS) 状态码
            // ❌ 问题 2：连接失败时仍尝试握手 → WSAENOTCONN
            if (!HandleConnectExCompletion(ovl, &sentBytes)) {
                Core::Logger::Error("GetQueuedCompletionStatusEx: ConnectEx 握手失败");
                // ❌ 问题 3：一个失败导致整个函数返回 FALSE
                return FALSE;
            }
        }
    }
}
```

### 2.2 问题链路

1. `getaddrinfo` 被 Hook，返回 FakeIP 虚拟地址（如 `198.18.x.x`）
2. 应用程序使用 `ConnectEx` 异步连接
3. FakeIP 网段在部分用户环境中存在路由问题 → 连接失败
4. `GetQueuedCompletionStatusEx` 返回失败事件
5. 代码**未检查 `OVERLAPPED_ENTRY.Internal`**，直接调用握手
6. Socket 未连接 → 发送数据失败 → **WSAENOTCONN (10057)**
7. `return FALSE` 导致后续健康连接也被中断 → 进程崩溃

### 2.3 FakeIP 与问题的关联

FakeIP **不是直接原因**，而是触发条件：

- FakeIP 返回的 `198.18.0.0/15` 网段在部分网络环境（VPN、企业防火墙、Docker overlay）中可能无法正确路由
- 连接失败率上升暴露了 IOCP 错误处理的缺陷

---

## 三、修复方案

### 3.1 修复清单

| 编号 | 模块 | 修复内容 | 严重程度 |
|------|------|----------|----------|
| FIX-1 | Hooks.cpp | IOCP 完成事件状态检查 | 🔴 高 |
| FIX-2 | Hooks.cpp | socket 连接状态预检 | 🟡 中 |
| FIX-3 | FakeIP.hpp | `IsFakeIP()` 加锁 | 🟢 低 |
| FIX-4 | FakeIP.hpp | 边界网段防御检查 | 🟢 低 |

---

### 3.2 FIX-1：IOCP 完成事件状态检查

**位置**：`src/hooks/Hooks.cpp`，函数 `DetourGetQueuedCompletionStatusEx`

**修改内容**：

```cpp
// 修改后
for (ULONG i = 0; i < *ulNumEntriesRemoved; i++) {
    LPOVERLAPPED ovl = lpCompletionPortEntries[i].lpOverlapped;
    if (!ovl) continue;
    
    // ✅ 检查 IOCP 完成状态（Internal 字段存储 NTSTATUS）
    // STATUS_SUCCESS = 0，非零表示操作失败
    NTSTATUS status = (NTSTATUS)lpCompletionPortEntries[i].Internal;
    if (status != 0) {
        // 连接失败：清理上下文，继续处理下一个事件（不阻断整个批次）
        DropConnectExContext(ovl);
        continue;
    }
    
    // 连接成功：执行握手
    DWORD sentBytes = 0;
    if (!HandleConnectExCompletion(ovl, &sentBytes)) {
        Core::Logger::Error("GetQueuedCompletionStatusEx: ConnectEx 握手失败");
        // ✅ 不再返回 FALSE，避免影响其他连接
    }
    if (sentBytes > 0) {
        lpCompletionPortEntries[i].dwNumberOfBytesTransferred = sentBytes;
    }
}
```

**同步修改**：
- `DetourGetQueuedCompletionStatus` 需要相同逻辑
- `DetourWSAGetOverlappedResult` 需要相同逻辑

---

### 3.3 FIX-2：socket 连接状态预检

**位置**：`src/hooks/Hooks.cpp`，函数 `DoProxyHandshake`

**修改内容**：

```cpp
static bool DoProxyHandshake(SOCKET s, const std::string& host, uint16_t port) {
    // ✅ 预检：确保 socket 已成功连接到代理服务器
    sockaddr_storage peerAddr{};
    int peerLen = sizeof(peerAddr);
    if (getpeername(s, (sockaddr*)&peerAddr, &peerLen) != 0) {
        int err = WSAGetLastError();
        Core::Logger::Error("代理握手: socket 未连接, sock=" + std::to_string((unsigned long long)s) +
                            ", 目标=" + host + ":" + std::to_string(port) +
                            ", WSA错误码=" + std::to_string(err));
        WSASetLastError(WSAENOTCONN);
        return false;
    }
    
    // ... 原有逻辑不变
}
```

---

### 3.4 FIX-3：`IsFakeIP()` 加锁

**位置**：`src/network/FakeIP.hpp`，函数 `IsFakeIP`

**问题**：当前实现读取 `m_mask` 和 `m_baseIp` 时未加锁，理论上存在 data race

**修改内容**：

```cpp
// 修改前
bool IsFakeIP(uint32_t ipNetworkOrder) {
    EnsureInitialized();
    uint32_t ip = ntohl(ipNetworkOrder);
    return (ip & m_mask) == m_baseIp;
}

// 修改后
bool IsFakeIP(uint32_t ipNetworkOrder) {
    EnsureInitialized();
    std::lock_guard<std::mutex> lock(m_mtx);
    uint32_t ip = ntohl(ipNetworkOrder);
    return (ip & m_mask) == m_baseIp;
}
```

---

### 3.5 FIX-4：边界网段防御检查

**位置**：`src/network/FakeIP.hpp`，函数 `Alloc`

**问题**：当 CIDR 为 `/32` 时，`m_networkSize = 1`，但 `m_cursor` 初始化为 1，会导致 `offset >= networkSize`

**修改内容**：

```cpp
// 在 EnsureInitialized() 中增加边界检查
if (m_networkSize <= 2) {
    Core::Logger::Warn("FakeIP: CIDR 网段过小 (容量=" + std::to_string(m_networkSize) + 
                       ")，建议使用 /24 或更大网段");
}
```

---

## 四、技术债务更新

修复完成后，需更新 `docs/TECH_DEBT.md`：

- 将 TD-001 (FakeIP 映射表无限增长) 标记为 ✅ 已修复（已完成）
- 新增 TD-008 (IOCP 状态检查缺失) 标记为 ✅ 已修复

---

## 五、验证场景

修复后，用户应验证以下场景：

1. **正常代理**：启用 FakeIP 时 HTTP/HTTPS 请求正常
2. **异步连接**：Chromium 系应用（使用 `GetQueuedCompletionStatusEx`）正常
3. **连接失败恢复**：代理服务器短暂不可用后恢复正常
4. **高并发**：多个并发连接不会相互阻断
5. **关闭 FakeIP**：`fake_ip.enabled = false` 时行为不变

---

## 六、修改文件清单

| 文件 | 修改类型 | 说明 |
|------|----------|------|
| `src/hooks/Hooks.cpp` | 修改 | IOCP 状态检查、socket 预检 |
| `src/network/FakeIP.hpp` | 修改 | `IsFakeIP()` 加锁、边界检查 |
| `docs/TECH_DEBT.md` | 更新 | 记录新修复项 |
| `docs/fakeip-optimization-spec.md` | 新增 | 本文档 |
