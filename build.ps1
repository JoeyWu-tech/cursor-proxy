# ============================================================
#  Cursor-Proxy 编译脚本
#  PowerShell Build Script for Windows
# ============================================================
# 使用方法:
#   .\build.ps1              # 默认 Release x64 编译
#   .\build.ps1 -Config Debug
#   .\build.ps1 -Arch x86
#   .\build.ps1 -Config Debug -Arch x86
# ============================================================

param(
    [ValidateSet("Release", "Debug")]
    [string]$Config = "Release",
    
    [ValidateSet("x64", "x86")]
    [string]$Arch = "x64",
    
    [switch]$StaticRuntime,
    [switch]$DynamicRuntime,
    [switch]$Clean,
    [switch]$Help
)

# ============================================================
# 版本信息 (在此处统一管理版本号)
# ============================================================
$Version = "1.7"

# ============================================================
# 辅助函数
# ============================================================

function Write-Header {
    param([string]$Message)
    Write-Host ""
    Write-Host "============================================================" -ForegroundColor Cyan
    Write-Host "  $Message" -ForegroundColor Cyan
    Write-Host "============================================================" -ForegroundColor Cyan
}

function Write-Step {
    param([string]$Message)
    Write-Host "[*] $Message" -ForegroundColor Yellow
}

function Write-Success {
    param([string]$Message)
    Write-Host "[✓] $Message" -ForegroundColor Green
}

function Write-Error {
    param([string]$Message)
    Write-Host "[✗] $Message" -ForegroundColor Red
}

function Show-Help {
    Write-Host @"
Cursor-Proxy 编译脚本

用法:
    .\build.ps1 [参数]

参数:
    -Config <Release|Debug>  编译配置 (默认: Release)
    -Arch   <x64|x86>        目标架构 (默认: x64)
    -StaticRuntime           使用静态运行库 (/MT) (默认启用)
    -DynamicRuntime          使用动态运行库 (/MD)
    -Clean                   清理后重新编译
    -Help                    显示帮助信息

示例:
    .\build.ps1                      # Release x64 编译
    .\build.ps1 -Config Debug        # Debug x64 编译
    .\build.ps1 -Arch x86            # Release x86 编译
    .\build.ps1 -DynamicRuntime      # 使用动态运行库编译
    .\build.ps1 -Clean -Config Debug # 清理后 Debug 编译
"@
}

# ============================================================
# 主逻辑
# ============================================================

if ($Help) {
    Show-Help
    exit 0
}

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$BuildDir = Join-Path $ScriptDir "build-$Arch"
$OutputDir = Join-Path $ScriptDir "output"

# 默认启用静态运行库，降低运行库缺失导致的启动失败风险
$UseStaticRuntime = $true
if ($DynamicRuntime) { $UseStaticRuntime = $false }
elseif ($StaticRuntime) { $UseStaticRuntime = $true }
$RuntimeLabel = if ($UseStaticRuntime) { "静态(/MT)" } else { "动态(/MD)" }

Write-Header "Cursor-Proxy 编译开始"
Write-Host "  配置: $Config" -ForegroundColor White
Write-Host "  架构: $Arch" -ForegroundColor White
Write-Host "  运行库: $RuntimeLabel" -ForegroundColor White
Write-Host "  构建目录: $BuildDir" -ForegroundColor White
Write-Host ""

# ============================================================
# 步骤 1: 检查依赖
# ============================================================

Write-Step "检查依赖项..."

# 检查 CMake
$cmake = Get-Command cmake -ErrorAction SilentlyContinue
if (-not $cmake) {
    Write-Error "CMake 未找到，请确保 CMake 已安装并添加到 PATH"
    exit 1
}
Write-Success "CMake 已找到: $($cmake.Source)"

# 检查 nlohmann/json
$jsonHeader = Join-Path $ScriptDir "include\nlohmann\json.hpp"
if (-not (Test-Path $jsonHeader)) {
    Write-Step "下载 nlohmann/json (单头文件)..."
    $nlohmannDir = Join-Path $ScriptDir "include\nlohmann"
    if (-not (Test-Path $nlohmannDir)) {
        New-Item -ItemType Directory -Path $nlohmannDir -Force | Out-Null
    }
    try {
        Invoke-WebRequest -Uri "https://raw.githubusercontent.com/nlohmann/json/develop/single_include/nlohmann/json.hpp" -OutFile $jsonHeader
        Write-Success "nlohmann/json 下载完成"
    } catch {
        Write-Error "下载失败: $_"
        Write-Host "请手动下载 json.hpp 到 include/nlohmann/ 目录" -ForegroundColor Yellow
        exit 1
    }
} else {
    Write-Success "nlohmann/json 已存在"
}

# ============================================================
# 步骤 2: 清理 (可选)
# ============================================================

if ($Clean -and (Test-Path $BuildDir)) {
    Write-Step "清理构建目录..."
    Remove-Item -Recurse -Force $BuildDir
    Write-Success "构建目录已清理"
}

# ============================================================
# 步骤 3: 创建构建目录
# ============================================================

if (-not (Test-Path $BuildDir)) {
    Write-Step "创建构建目录..."
    New-Item -ItemType Directory -Path $BuildDir | Out-Null
}

# ============================================================
# 步骤 4: CMake 配置
# ============================================================

Write-Step "运行 CMake 配置..."

$cmakeArch = if ($Arch -eq "x64") { "x64" } else { "Win32" }

Push-Location $BuildDir
try {
    $cmakeArgs = @(
        "..",
        "-G", "Visual Studio 17 2022",
        "-A", $cmakeArch
    )
    if ($UseStaticRuntime) {
        $cmakeArgs += "-DSTATIC_RUNTIME=ON"
    } else {
        $cmakeArgs += "-DSTATIC_RUNTIME=OFF"
    }
    
    $cmakeResult = & cmake @cmakeArgs 2>&1
    if ($LASTEXITCODE -ne 0) {
        Write-Error "CMake 配置失败"
        Write-Host $cmakeResult -ForegroundColor Red
        exit 1
    }
    Write-Success "CMake 配置完成"
} finally {
    Pop-Location
}

# ============================================================
# 步骤 5: 编译
# ============================================================

Write-Step "开始编译 ($Config $Arch)..."

Push-Location $BuildDir
try {
    $buildResult = & cmake --build . --config $Config 2>&1
    if ($LASTEXITCODE -ne 0) {
        Write-Error "编译失败"
        Write-Host $buildResult -ForegroundColor Red
        exit 1
    }
    Write-Success "编译完成"
} finally {
    Pop-Location
}

# ============================================================
# 步骤 6: 查找输出文件
# ============================================================

Write-Step "查找编译产物..."

$dllPattern = if ($Config -eq "Debug") { "version*.dll" } else { "version.dll" }
$dllPath = Get-ChildItem -Path $BuildDir -Recurse -Filter $dllPattern | Select-Object -First 1

if (-not $dllPath) {
    Write-Error "未找到编译产物 DLL"
    exit 1
}

Write-Success "找到 DLL: $($dllPath.FullName)"

# ============================================================
# 步骤 7: 创建输出目录并复制文件
# ============================================================

Write-Step "创建输出目录..."

if (-not (Test-Path $OutputDir)) {
    New-Item -ItemType Directory -Path $OutputDir | Out-Null
}

Copy-Item $dllPath.FullName -Destination $OutputDir -Force
Write-Success "DLL 已复制到 output 目录"

# ============================================================
# 步骤 8: 生成配置文件
# ============================================================

Write-Step "生成配置文件..."

$configJson = @{
    "_comment" = "Cursor-Proxy 配置文件 (基于 antigravity-proxy)"
    "_version" = $Version
    "_build" = @{
        "date" = (Get-Date -Format "yyyy-MM-dd HH:mm:ss")
        "config" = $Config
        "arch" = $Arch
    }
    log_level = "debug"
    proxy = @{
        host = "127.0.0.1"
        port = 7890
        type = "socks5"
    }
    fake_ip = @{
        enabled = $true
        cidr = "198.18.0.0/15"
    }
    timeout = @{
        connect = 30000
        send = 30000
        recv = 30000
    }
    traffic_logging = $false
    child_injection = $true
    child_injection_mode = "filtered"
    child_injection_exclude = @()
    target_processes = @("Cursor.exe")
    proxy_rules = @{
        allowed_ports = @(80, 443)
        dns_mode = "direct"
        ipv6_mode = "proxy"
        udp_mode = "block"
        udp_fallback = "block"
        routing = @{
            enabled = $true
            priority_mode = "order"
            default_action = "proxy"
            use_default_private = $true
            rules = @()
        }
    }
} | ConvertTo-Json -Depth 5

$configPath = Join-Path $OutputDir "config.json"
$configJson | Out-File -FilePath $configPath -Encoding UTF8
Write-Success "配置文件已生成: $configPath"

# ============================================================
# 步骤 9: 生成使用说明
# ============================================================

Write-Step "生成使用说明..."

$usageDoc = @'
# Cursor-Proxy 使用说明

基于 antigravity-proxy 项目修改，专门针对 Cursor 编辑器优化。

## 快速开始
1. 将 version.dll 和 config.json 复制到 Cursor.exe 同级目录
2. 编辑 config.json 中的代理端口（默认 7890）
3. 启动 Cursor

详细配置请参考: https://github.com/yuaotian/antigravity-proxy
'@

$usagePath = Join-Path $OutputDir "使用说明.md"
$usageDoc | Out-File -FilePath $usagePath -Encoding UTF8
Write-Success "使用说明已生成: $usagePath"

# ============================================================
# 完成
# ============================================================

Write-Header "编译完成!"
Write-Host ""
Write-Host "输出目录: $OutputDir" -ForegroundColor Green
Write-Host ""
Write-Host "生成的文件:" -ForegroundColor White
Get-ChildItem $OutputDir | ForEach-Object {
    Write-Host "  - $($_.Name)" -ForegroundColor Gray
}
Write-Host ""
Write-Host "下一步: 将 output 目录中的文件复制到目标程序目录即可使用。" -ForegroundColor Yellow
Write-Host ""
