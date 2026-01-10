# Antigravity-Proxy 技术债务清单

> 代码审查日期: 2026-01-08
> 审查范围: 内存泄漏、内存增长、异常处理、崩溃风险

---

## 🔴 高严重程度 (High Priority)

### ~~TD-001: FakeIP 映射表无限增长~~ ✅ 已修复
- **文件**: `src/network/FakeIP.hpp`
- **问题**: ~~`m_ipToDomain` 和 `m_domainToIp` 只增不删~~
- **状态**: **已通过 Ring Buffer 策略修复** (2026-01-11)
- **修复说明**: 使用循环复用的地址池策略，游标回绕时自动覆盖旧映射并清理反向索引

### TD-002: ConnectEx 异步上下文泄漏
- **文件**: `src/hooks/Hooks.cpp:77,212-224`
- **问题**: `g_connectExPending` 在连接超时/取消时不清理
- **触发**: 异步连接未正常完成
- **修复**: 上下文添加时间戳，定期清理超时条目

### TD-003: 跳过进程日志 Map 无清理
- **文件**: `src/hooks/Hooks.cpp:83-84`
- **问题**: `g_loggedSkipProcesses` 只增不删
- **触发**: 大量不同进程名创建
- **修复**: 设置最大条目数或定期清理

---

## 🟡 中严重程度 (Medium Priority)

### TD-004: 日志文件无限增长
- **文件**: `src/core/Logger.hpp:38-41`
- **问题**: `proxy.log` 追加模式无轮转
- **建议**: 日志轮转或大小限制

### TD-005: 原始函数指针空检查
- **文件**: `src/hooks/Hooks.cpp` 多处
- **问题**: 部分 fpXxx 调用前缺少 NULL 检查
- **建议**: 统一添加检查

### TD-006: DllMain 中复杂操作
- **文件**: `src/main.cpp:21-47`
- **问题**: Loader Lock 下执行文件 I/O
- **状态**: DLL 代理常见模式，已知风险

---

## 🟢 低严重程度 (Low Priority)

### TD-007: thread_local 卸载风险
- **文件**: `src/hooks/Hooks.cpp:65`
- **问题**: DLL 卸载时 thread_local 析构
- **状态**: Windows 已知限制，触发概率低

---

## 修复优先级建议

1. **短期**: TD-001 (FakeIP 上限)
2. **中期**: TD-002, TD-003 (Map 清理)
3. **长期**: TD-004 (日志轮转)
