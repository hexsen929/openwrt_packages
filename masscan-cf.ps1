<#
.SYNOPSIS
    Cloudflare reverse proxy node scanner based on masscan, reimagined for Windows PowerShell.

.DESCRIPTION
    This script is a PowerShell rewrite of the traditional Bash-based "masscan CF" tooling. It automates
    the end-to-end workflow for enumerating Cloudflare ASN IPv4 ranges, scanning them with masscan, 
    validating HTTPS availability with goscan (or a PowerShell fallback), performing RTT sampling via
    concurrent curl probes, and optionally executing throughput tests against Cloudflare's Arch Linux mirror.

    Key capabilities include:
      * Dependency detection for masscan, goscan, curl and prerequisite hints for Windows/Npcap.
      * Automatic network adapter discovery using Get-NetAdapter, with interactive selection support.
      * Single-AS or batch-AS processing modes, with configurable port, scan rate and coroutine counts.
      * ASN CIDR retrieval from https://whois.ipip.net with robust regex parsing and /24 subnet splitting.
      * Masscan execution with customizable adapter parameters and output parsing into structured datasets.
      * HTTPS validation using goscan; a native PowerShell validator is provided as a safety net.
      * RTT testing implemented with background jobs, real-time progress updates, and Cloudflare trace parsing.
      * Optional download speed benchmarking via curl and Cloudflare's Arch Linux mirror.
      * Structured CSV exports alongside supplemental mapping files (colo.txt) for Cloudflare POP metadata.

    Tested with Windows PowerShell 5.1 and PowerShell 7+. For best performance, run with elevated privileges
    and ensure Npcap (https://npcap.com) is installed to grant masscan raw socket access.

.NOTES
    Author : cto.new automated agent
    Version: 1.0.0
    Date   : 2024-10-24

    运行提示:
      * 若系统启用了执行策略限制，可使用附带的 masscan-cf.cmd 启动脚本，
        该批处理会自动以 Bypass 模式调用 PowerShell。
      * 也可在提升权限的 PowerShell 中执行：
            powershell -ExecutionPolicy Bypass -File .\masscan-cf.ps1

#>

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8

# region: global paths and constants
$Script:ScriptRoot = Split-Path -Parent $PSCommandPath
$Script:AsnDirectory = Join-Path $Script:ScriptRoot 'asn'
$Script:LogDirectory = Join-Path $Script:ScriptRoot 'log'
$Script:ColoFile = Join-Path $Script:ScriptRoot 'colo.txt'

# ensure base directories exist at script loading time
foreach ($directory in @($Script:AsnDirectory, $Script:LogDirectory)) {
    if (-not (Test-Path -LiteralPath $directory)) {
        New-Item -ItemType Directory -Path $directory | Out-Null
    }
}

#region helper functions

function Write-Info {
    <#
        .SYNOPSIS
            Prints an informational message in cyan for user-friendly output.
    #>
    param(
        [Parameter(Mandatory = $true)][string]$Message
    )
    Write-Host "[*] $Message" -ForegroundColor Cyan
}

function Write-Warn {
    <#
        .SYNOPSIS
            Prints a warning message in yellow.
    #>
    param(
        [Parameter(Mandatory = $true)][string]$Message
    )
    Write-Host "[!] $Message" -ForegroundColor Yellow
}

function Write-ErrorMessage {
    <#
        .SYNOPSIS
            Prints an error message in red without stopping execution.
    #>
    param(
        [Parameter(Mandatory = $true)][string]$Message
    )
    Write-Host "[x] $Message" -ForegroundColor Red
}

function ConvertTo-IPv4UInt32 {
    <#
        .SYNOPSIS
            Converts an IPv4 string into an unsigned 32-bit integer.
    #>
    param(
        [Parameter(Mandatory = $true)][string]$IpAddress
    )

    try {
        $ip = [System.Net.IPAddress]::Parse($IpAddress)
        $bytes = $ip.GetAddressBytes()
        [Array]::Reverse($bytes)
        return [BitConverter]::ToUInt32($bytes, 0)
    }
    catch {
        throw "无法解析 IPv4 地址: $IpAddress"
    }
}

function ConvertFrom-IPv4UInt32 {
    <#
        .SYNOPSIS
            Converts an unsigned 32-bit integer to a dotted IPv4 representation.
    #>
    param(
        [Parameter(Mandatory = $true)][uint32]$Value
    )

    $bytes = [BitConverter]::GetBytes($Value)
    [Array]::Reverse($bytes)
    return [System.Net.IPAddress]::new($bytes).ToString()
}

function Split-Subnet {
    <#
        .SYNOPSIS
            Splits an arbitrary IPv4 CIDR block into /24 subnets when required.
        .DESCRIPTION
            CIDRs with a prefix length smaller than /24 are expanded into their constituent /24 networks to
            optimize the subsequent masscan target list. Prefixes of /24 or smaller granularity (/25+)
            are returned verbatim. All CIDRs between /8 and /32 are supported.
    #>
    param(
        [Parameter(Mandatory = $true)][string]$Cidr
    )

    $parts = $Cidr.Split('/')
    if ($parts.Count -ne 2) {
        throw "CIDR 表达式无效: $Cidr"
    }

    $network = $parts[0].Trim()
    $prefix = [int]$parts[1]

    if ($prefix -lt 8 -or $prefix -gt 32) {
        throw "暂不支持的掩码长度: /$prefix"
    }

    $networkValue = ConvertTo-IPv4UInt32 -IpAddress $network

    if ($prefix -ge 24) {
        return ,"$network/$prefix"
    }

    # compute the total number of /24 subnets contained in this network
    $subnetCount = [math]::Pow(2, 24 - $prefix)
    $subnets = New-Object 'System.Collections.Generic.List[string]'

    for ($i = 0; $i -lt $subnetCount; $i++) {
        $startValue = $networkValue + ([uint32]$i * 256)
        $subnets.Add("$(ConvertFrom-IPv4UInt32 -Value $startValue)/24")
    }

    return $subnets
}

function ConvertTo-RegionName {
    <#
        .SYNOPSIS
            Converts an ISO-3166 alpha-2 country code into its native display name.
    #>
    param(
        [Parameter()][string]$CountryCode
    )

    if ([string]::IsNullOrWhiteSpace($CountryCode)) {
        return '未知'
    }

    try {
        $region = [System.Globalization.RegionInfo]::new($CountryCode.ToUpperInvariant())
        return $region.NativeName
    }
    catch {
        return $CountryCode.ToUpperInvariant()
    }
}

function Get-IPTypeFromTrace {
    <#
        .SYNOPSIS
            Classifies Cloudflare IP types using trace metadata.
        .DESCRIPTION
            Basic heuristics leveraging Cloudflare trace keys. The logic can be extended to match
            organization-specific definitions for Official/Transit/Tunnel nodes.
    #>
    param(
        [Parameter(Mandatory = $true)][hashtable]$TraceData
    )

    if ($TraceData.ContainsKey('warp') -and $TraceData['warp'] -eq 'on') {
        return '隧道'
    }

    if ($TraceData.ContainsKey('gateway') -and $TraceData['gateway'] -eq 'on') {
        return '中转'
    }

    return '官方'
}

#endregion helper functions

function Test-Dependencies {
    <#
        .SYNOPSIS
            Validates external binary dependencies and provides installation guidance.
        .OUTPUTS
            PSCustomObject with MasscanPath, GoscanPath, CurlPath, UseGoscan (bool), UseFallback (bool).
    #>
    param(
        [Parameter()][string]$WorkingDirectory = $Script:ScriptRoot
    )

    Write-Info '正在检查外部依赖...'

    $masscanCandidates = @('masscan.exe', 'masscan')
    $masscanPath = $null
    foreach ($candidate in $masscanCandidates) {
        $cmd = Get-Command -Name $candidate -ErrorAction SilentlyContinue
        if ($cmd) {
            $masscanPath = $cmd.Source
            break
        }
    }

    if (-not $masscanPath) {
        $localMasscan = Join-Path $WorkingDirectory 'masscan.exe'
        if (Test-Path -LiteralPath $localMasscan) {
            $masscanPath = $localMasscan
        }
    }

    if (-not $masscanPath) {
        Write-ErrorMessage '未检测到 masscan，可执行文件是运行扫描的必要条件。'
        Write-Warn '请从 https://github.com/robertdavidgraham/masscan/releases 下载 Windows 版本并将其添加到 PATH。'
        Write-Warn '运行 masscan 需要管理员权限以及 Npcap (https://npcap.com)。'
        throw '缺少 masscan 依赖'
    }

    $goscanCandidates = @('goscan.exe', 'goscan')
    $goscanPath = $null
    foreach ($candidate in $goscanCandidates) {
        $cmd = Get-Command -Name $candidate -ErrorAction SilentlyContinue
        if ($cmd) {
            $goscanPath = $cmd.Source
            break
        }
    }

    if (-not $goscanPath) {
        $localGoscan = Join-Path $WorkingDirectory 'goscan.exe'
        if (Test-Path -LiteralPath $localGoscan) {
            $goscanPath = $localGoscan
        }
    }

    if (-not $goscanPath) {
        Write-Warn '未检测到 goscan，可选地可从团队提供的二进制包或内部仓库下载。'
        Write-Warn '脚本将尝试使用内置的 PowerShell HTTPS 验证逻辑作为兜底方案。'
    }

    $curlCmd = Get-Command -Name 'curl.exe' -ErrorAction SilentlyContinue
    if (-not $curlCmd) {
        Write-ErrorMessage '系统未检测到 curl.exe，建议安装 Windows 10 自带的 curl 或使用 Git for Windows 自带版本。'
        throw '缺少 curl 依赖'
    }

    Write-Info "masscan: $masscanPath"
    if ($goscanPath) {
        Write-Info "goscan : $goscanPath"
    }
    else {
        Write-Warn 'goscan : 未找到，将使用内置校验函数'
    }
    Write-Info "curl   : $($curlCmd.Source)"

    return [PSCustomObject]@{
        MasscanPath = $masscanPath
        GoscanPath  = $goscanPath
        CurlPath    = $curlCmd.Source
        UseGoscan   = [bool]$goscanPath
    }
}

function Get-NetworkAdapter {
    <#
        .SYNOPSIS
            Detects available network adapters and lets the operator choose one.
        .OUTPUTS
            PSCustomObject containing adapter metadata (Alias, InterfaceIndex, MacAddress, IPv4).
    #>
    Write-Info '正在获取可用网络适配器...'

    try {
        $adapters = Get-NetAdapter -ErrorAction Stop | Where-Object { $_.Status -eq 'Up' }
    }
    catch {
        Write-Warn 'Get-NetAdapter 不可用，可能缺少 NetAdapter 模块或当前 PowerShell 版本不支持。'
        return $null
    }

    if (-not $adapters) {
        throw '未发现处于 Up 状态的物理网卡，请检查网络连接。'
    }

    $index = 1
    foreach ($adapter in $adapters) {
        Write-Host ("[{0}] {1,-20} MAC:{2} 速率:{3}" -f $index, $adapter.InterfaceAlias, $adapter.MacAddress, $adapter.LinkSpeed) -ForegroundColor Green
        $index++
    }

    $selection = $null
    if ($adapters.Count -eq 1) {
        $selection = $adapters[0]
        Write-Info "自动选择网卡: $($selection.InterfaceAlias)"
    }
    else {
        do {
            $input = Read-Host "请选择用于 masscan 的网卡编号 (1-$($adapters.Count))"
            [int]$choice = 0
            if ([int]::TryParse($input, [ref]$choice)) {
                if ($choice -ge 1 -and $choice -le $adapters.Count) {
                    $selection = $adapters[$choice - 1]
                }
            }
            if (-not $selection) {
                Write-Warn '输入无效，请重新选择。'
            }
        } while (-not $selection)
    }

    $ipv4 = Get-NetIPAddress -InterfaceIndex $selection.InterfaceIndex -AddressFamily IPv4 -ErrorAction SilentlyContinue |
        Where-Object { $_.PrefixOrigin -ne 'WellKnown' } |
        Select-Object -First 1

    $ipv4Address = $null
    if ($ipv4) {
        $ipv4Address = $ipv4.IPAddress
    }
    else {
        Write-Warn '未能自动解析 IPv4 地址，请稍后手动指定 adapter 参数。'
    }

    return [PSCustomObject]@{
        InterfaceAlias  = $selection.InterfaceAlias
        InterfaceIndex  = $selection.InterfaceIndex
        MacAddress      = $selection.MacAddress
        IPv4Address     = $ipv4Address
    }
}

function Get-ColoData {
    <#
        .SYNOPSIS
            Downloads Cloudflare POP metadata and stores it locally.
        .OUTPUTS
            Hashtable keyed by IATA code with rich location metadata.
    #>
    Write-Info '正在刷新 Cloudflare 数据中心列表 (colo)...'

    try {
        $response = Invoke-RestMethod -Uri 'https://speed.cloudflare.com/locations' -Method Get -TimeoutSec 30
    }
    catch {
        Write-Warn "获取 Cloudflare 站点信息失败: $($_.Exception.Message)"
        if (Test-Path -LiteralPath $Script:ColoFile) {
            Write-Warn '将尝试从本地缓存加载 colo 映射。'
            $cachedMap = @{}
            Get-Content -LiteralPath $Script:ColoFile | ForEach-Object {
                if ([string]::IsNullOrWhiteSpace($_)) { return }
                $cells = $_.Split('|')
                if ($cells.Count -ge 4) {
                    $cachedMap[$cells[0]] = [PSCustomObject]@{
                        Iata    = $cells[0]
                        City    = $cells[1]
                        Country = $cells[2]
                        Region  = $cells[3]
                    }
                }
            }
            return $cachedMap
        }
        return @{}
    }

    $map = @{}
    $lines = New-Object 'System.Collections.Generic.List[string]'

    foreach ($entry in $response) {
        $iata = $entry.iata
        if ([string]::IsNullOrWhiteSpace($iata)) { continue }
        $map[$iata] = [PSCustomObject]@{
            Iata    = $entry.iata
            City    = $entry.city
            Country = $entry.cca2
            Region  = $entry.region
        }
        $lines.Add("$($entry.iata)|$($entry.city)|$($entry.cca2)|$($entry.region)")
    }

    if ($lines.Count -gt 0) {
        $lines | Set-Content -LiteralPath $Script:ColoFile -Encoding UTF8
    }

    return $map
}

function Get-ASNData {
    <#
        .SYNOPSIS
            Retrieves IPv4 CIDR blocks for a given ASN and prepares the target list.
        .OUTPUTS
            PSCustomObject with Asn, Targets, TargetFile.
    #>
    param(
        [Parameter(Mandatory = $true)][string]$Asn,
        [Parameter()][switch]$ForceRefresh
    )

    $normalized = $Asn.Trim().ToUpperInvariant()
    $normalized = $normalized -replace '^AS', ''

    $targetFile = Join-Path $Script:AsnDirectory "AS$normalized-targets.txt"

    if ((-not $ForceRefresh) -and (Test-Path -LiteralPath $targetFile)) {
        Write-Info "检测到本地缓存 AS$normalized-targets.txt，将直接使用。"
        $targets = Get-Content -LiteralPath $targetFile | Where-Object { -not [string]::IsNullOrWhiteSpace($_) }
        return [PSCustomObject]@{
            Asn        = "AS$normalized"
            Targets    = $targets
            TargetFile = $targetFile
        }
    }

    $url = "https://whois.ipip.net/AS$normalized"
    Write-Info "正在抓取 AS$normalized 的 CIDR 信息: $url"

    try {
        $response = Invoke-WebRequest -Uri $url -UseBasicParsing -TimeoutSec 30
    }
    catch {
        throw "获取 AS 信息失败: $($_.Exception.Message)"
    }

    $pattern = '((?:\d{1,3}\.){3}\d{1,3}/\d{1,2})'
    $matches = [System.Text.RegularExpressions.Regex]::Matches($response.Content, $pattern)

    if ($matches.Count -eq 0) {
        throw "未从 whois.ipip.net 获取到 AS$normalized 的 IPv4 列表。"
    }

    $expanded = New-Object 'System.Collections.Generic.List[string]'
    foreach ($match in $matches) {
        $cidr = $match.Value
        foreach ($subnet in (Split-Subnet -Cidr $cidr)) {
            $expanded.Add($subnet)
        }
    }

    $distinct = $expanded |
        Sort-Object -Property { ConvertTo-IPv4UInt32 -IpAddress (($_ -split '/')[0]) }, { [int]($_ -split '/')[1] } -Unique

    $distinct | Set-Content -LiteralPath $targetFile -Encoding UTF8
    Write-Info "AS$normalized 共计生成 $($distinct.Count) 个扫描子网。"

    return [PSCustomObject]@{
        Asn        = "AS$normalized"
        Targets    = $distinct
        TargetFile = $targetFile
    }
}

function Invoke-MasscanScan {
    <#
        .SYNOPSIS
            Executes masscan against the prepared target list.
        .OUTPUTS
            PSCustomObject with DataFile, AllIpFile, DiscoveredPorts (list).
    #>
    param(
        [Parameter(Mandatory = $true)][string]$MasscanPath,
        [Parameter(Mandatory = $true)][string]$TargetFile,
        [Parameter(Mandatory = $true)][string]$Ports,
        [Parameter(Mandatory = $true)][int]$Rate,
        [Parameter()][pscustomobject]$AdapterInfo,
        [Parameter()][int]$MaxRetries = 1
    )

    if (-not (Test-Path -LiteralPath $TargetFile)) {
        throw "目标列表不存在: $TargetFile"
    }

    $dataFile = Join-Path $Script:LogDirectory 'data.txt'
    $allIpFile = Join-Path $Script:LogDirectory 'allip.txt'

    if (Test-Path -LiteralPath $dataFile) { Remove-Item -LiteralPath $dataFile -Force }
    if (Test-Path -LiteralPath $allIpFile) { Remove-Item -LiteralPath $allIpFile -Force }

    $arguments = @('-p', $Ports, '--rate', $Rate.ToString(), '-iL', $TargetFile, '--open-only', '-oL', $dataFile)

    if ($AdapterInfo -and $AdapterInfo.IPv4Address) {
        $arguments += @('--adapter-ip', $AdapterInfo.IPv4Address)
    }

    if ($AdapterInfo -and $AdapterInfo.MacAddress) {
        $mac = $AdapterInfo.MacAddress -replace '-', ':'
        $arguments += @('--adapter-mac', $mac)
    }

    Write-Info "masscan 命令: $MasscanPath $($arguments -join ' ')"

    $attempt = 0
    do {
        $attempt++
        Write-Info "开始执行 masscan，尝试 $attempt"
        $process = Start-Process -FilePath $MasscanPath -ArgumentList $arguments -NoNewWindow -Wait -PassThru
        $exitCode = $process.ExitCode
        if ($exitCode -eq 0) { break }
        Write-Warn "masscan 返回非零退出码 ($exitCode)，将重试" 
    } while ($attempt -le $MaxRetries)

    if ($exitCode -ne 0) {
        throw "masscan 执行失败，退出码 $exitCode"
    }

    if (-not (Test-Path -LiteralPath $dataFile)) {
        throw 'masscan 未生成 data.txt 输出文件'
    }

    $openHosts = New-Object 'System.Collections.Generic.HashSet[string]'
    $portsFound = New-Object 'System.Collections.Generic.HashSet[string]'

    foreach ($line in Get-Content -LiteralPath $dataFile) {
        if ([string]::IsNullOrWhiteSpace($line)) { continue }
        if ($line -match '^open\s+\S+\s+(\d+)\s+((?:\d{1,3}\.){3}\d{1,3})') {
            $portsFound.Add($Matches[1]) | Out-Null
            $openHosts.Add($Matches[2]) | Out-Null
        }
    }

    $openHosts | Set-Content -LiteralPath $allIpFile -Encoding UTF8
    Write-Info "masscan 完成，共识别 $($openHosts.Count) 个开放 IP。"

    return [PSCustomObject]@{
        DataFile        = $dataFile
        AllIpFile       = $allIpFile
        OpenIpCount     = $openHosts.Count
        DiscoveredPorts = $portsFound
    }
}

function Invoke-GoscanValidation {
    <#
        .SYNOPSIS
            Validates HTTPS availability using goscan when available.
        .OUTPUTS
            Array of PSCustomObject with IP and optional metadata.
    #>
    param(
        [Parameter(Mandatory = $true)][string]$GoscanPath,
        [Parameter(Mandatory = $true)][string]$AllIpFile,
        [Parameter(Mandatory = $true)][string]$RealIpFile,
        [Parameter(Mandatory = $true)][string]$Domain,
        [Parameter(Mandatory = $true)][string]$Ports,
        [Parameter(Mandatory = $true)][int]$Concurrency
    )

    if (Test-Path -LiteralPath $RealIpFile) { Remove-Item -LiteralPath $RealIpFile -Force }

    # default argument template; adjust according to actual goscan build semantics if required
    $arguments = @(
        '--input', $AllIpFile,
        '--port', $Ports,
        '--domain', $Domain,
        '--scheme', 'https',
        '--output', $RealIpFile,
        '--concurrency', $Concurrency
    )

    Write-Info "goscan 命令: $GoscanPath $($arguments -join ' ')"
    $process = Start-Process -FilePath $GoscanPath -ArgumentList $arguments -NoNewWindow -Wait -PassThru
    if ($process.ExitCode -ne 0) {
        throw "goscan 执行失败，退出码 $($process.ExitCode)"
    }

    if (-not (Test-Path -LiteralPath $RealIpFile)) {
        throw 'goscan 未生成 realip.txt 文件'
    }

    $parsed = @()
    foreach ($line in Get-Content -LiteralPath $RealIpFile) {
        if ([string]::IsNullOrWhiteSpace($line)) { continue }
        $cells = $line.Split(',', ' ', "`t") | Where-Object { -not [string]::IsNullOrWhiteSpace($_) }
        $ip = $cells[0]
        $parsed += [PSCustomObject]@{
            IPAddress = $ip
            RawLine   = $line
        }
    }

    return $parsed
}

function Invoke-PowerShellValidation {
    <#
        .SYNOPSIS
            Fallback HTTPS validator using PowerShell and curl.
    #>
    param(
        [Parameter(Mandatory = $true)][string]$CurlPath,
        [Parameter(Mandatory = $true)][string]$AllIpFile,
        [Parameter(Mandatory = $true)][string]$RealIpFile,
        [Parameter(Mandatory = $true)][string]$Domain,
        [Parameter(Mandatory = $true)][int]$Port,
        [Parameter(Mandatory = $true)][int]$Concurrency
    )

    if (Test-Path -LiteralPath $RealIpFile) { Remove-Item -LiteralPath $RealIpFile -Force }

    $ips = Get-Content -LiteralPath $AllIpFile | Where-Object { -not [string]::IsNullOrWhiteSpace($_) }
    if (-not $ips) { return @() }

    Write-Info "开始执行 PowerShell Fallback HTTPS 验证，总计 $($ips.Count) 个 IP"

    $jobs = @()
    $results = New-Object 'System.Collections.Concurrent.ConcurrentBag[object]'
    $total = $ips.Count
    $completed = 0

    foreach ($ip in $ips) {
        while (($jobs | Where-Object { $_.State -eq 'Running' }).Count -ge $Concurrency) {
            $finished = Wait-Job -Job $jobs -Any -Timeout 2
            if ($finished) {
                $output = Receive-Job -Job $finished -ErrorAction SilentlyContinue
                if ($output) { $results.Add($output) }
                Remove-Job -Job $finished
                $jobs = $jobs | Where-Object { $_.Id -ne $finished.Id }
                $completed++
                Write-Progress -Activity 'Fallback HTTPS 验证' -Status "已完成 $completed/$total" -PercentComplete (($completed / $total) * 100)
            }
        }

        $jobs += Start-Job -ScriptBlock {
            param($ip, $curlPath, $domain, $port)
            $arguments = @(
                '--silent', '--show-error', '--connect-timeout', '5', '--max-time', '15',
                '--resolve', "$domain`:$port`:$ip",
                "https://$domain",
                '--output', 'NUL'
            )
            & $curlPath @arguments
            $exit = $LASTEXITCODE
            if ($exit -eq 0) {
                return [PSCustomObject]@{ IPAddress = $ip }
            }
            return $null
        } -ArgumentList $ip, $CurlPath, $Domain, $Port
    }

    while ($jobs.Count -gt 0) {
        $finished = Wait-Job -Job $jobs -Any -Timeout 5
        if (-not $finished) { continue }
        $output = Receive-Job -Job $finished -ErrorAction SilentlyContinue
        if ($output) { $results.Add($output) }
        Remove-Job -Job $finished
        $jobs = $jobs | Where-Object { $_.Id -ne $finished.Id }
        $completed++
        Write-Progress -Activity 'Fallback HTTPS 验证' -Status "已完成 $completed/$total" -PercentComplete (($completed / $total) * 100)
    }

    Write-Progress -Activity 'Fallback HTTPS 验证' -Completed -Status '完成'

    $valid = $results.ToArray() | Where-Object { $_ -ne $null }
    $valid | ForEach-Object { $_.IPAddress } | Set-Content -LiteralPath $RealIpFile -Encoding UTF8
    Write-Info "PowerShell 验证通过 IP 数量: $($valid.Count)"

    return $valid
}

function Test-RealIP {
    <#
        .SYNOPSIS
            Wrapper that orchestrates goscan or PowerShell fallback validation.
        .OUTPUTS
            Array of PSCustomObject with IPAddress metadata.
    #>
    param(
        [Parameter()][string]$GoscanPath,
        [Parameter(Mandatory = $true)][string]$CurlPath,
        [Parameter(Mandatory = $true)][string]$AllIpFile,
        [Parameter(Mandatory = $true)][string]$Domain,
        [Parameter(Mandatory = $true)][string]$Ports,
        [Parameter(Mandatory = $true)][int]$Concurrency
    )

    $realIpFile = Join-Path $Script:LogDirectory 'realip.txt'

    $portToken = (($Ports -split ',')[0]).Trim()
    [int]$portNumber = 443
    if (-not [int]::TryParse($portToken, [ref]$portNumber)) {
        Write-Warn 'REAL IP 验证端口解析失败，默认使用 443'
        $portNumber = 443
    }

    if ($GoscanPath) {
        try {
            Write-Info '开始调用 goscan 进行 REAL IP 验证'
            $realIps = Invoke-GoscanValidation -GoscanPath $GoscanPath -AllIpFile $AllIpFile -RealIpFile $realIpFile -Domain $Domain -Ports $Ports -Concurrency $Concurrency
            if ($realIps -and $realIps.Count -gt 0) {
                return $realIps
            }
            Write-Warn 'goscan 没有返回有效结果，将退回 PowerShell 校验方案。'
        }
        catch {
            Write-Warn "goscan 执行失败: $($_.Exception.Message)，将使用 PowerShell 兜底验证。"
        }
    }

    return Invoke-PowerShellValidation -CurlPath $CurlPath -AllIpFile $AllIpFile -RealIpFile $realIpFile -Domain $Domain -Port $portNumber -Concurrency ([math]::Min(20, [math]::Max(1, $Concurrency)))
}

function Test-RTT {
    <#
        .SYNOPSIS
            Executes concurrent Cloudflare trace probes to collect RTT and POP data.
    #>
    param(
        [Parameter(Mandatory = $true)][pscustomobject[]]$RealIpEntries,
        [Parameter(Mandatory = $true)][string]$CurlPath,
        [Parameter(Mandatory = $true)][string]$Domain,
        [Parameter(Mandatory = $true)][int]$Port,
        [Parameter(Mandatory = $true)][int]$Concurrency,
        [Parameter()][hashtable]$ColoMap
    )

    if (-not $RealIpEntries -or $RealIpEntries.Count -eq 0) {
        return @()
    }

    Write-Info "开始进行 RTT 测试，共计 $($RealIpEntries.Count) 个 REAL IP"

    $jobs = @()
    $results = New-Object 'System.Collections.Concurrent.ConcurrentBag[object]'
    $total = $RealIpEntries.Count
    $completed = 0

    foreach ($entry in $RealIpEntries) {
        $ip = $entry.IPAddress

        while (($jobs | Where-Object { $_.State -eq 'Running' }).Count -ge $Concurrency) {
            $finished = Wait-Job -Job $jobs -Any -Timeout 2
            if ($finished) {
                $output = Receive-Job -Job $finished -ErrorAction SilentlyContinue
                if ($output) { $results.Add($output) }
                Remove-Job -Job $finished
                $jobs = $jobs | Where-Object { $_.Id -ne $finished.Id }
                $completed++
                Write-Progress -Activity 'RTT 信息采集' -Status "已完成 $completed/$total" -PercentComplete (($completed / $total) * 100)
            }
        }

        $jobs += Start-Job -ScriptBlock {
            param($ip, $curlPath, $domain, $port)
            $metaToken = '__META__'
            $arguments = @(
                '--silent', '--show-error', '--connect-timeout', '5', '--max-time', '15',
                '--resolve', "$domain`:$port`:$ip",
                "https://$domain/cdn-cgi/trace",
                '--write-out', "$metaToken%{time_connect}|%{time_total}|%{speed_download}",
                '--output', '-'
            )
            $rawOutput = & $curlPath @arguments 2>&1
            $exitCode = $LASTEXITCODE

            if ($rawOutput -is [System.Array]) {
                $rawOutput = $rawOutput -join "`n"
            }

            if ($exitCode -ne 0 -or [string]::IsNullOrWhiteSpace($rawOutput)) {
                return [PSCustomObject]@{
                    IPAddress = $ip
                    Success   = $false
                    Error     = $rawOutput
                }
            }

            $delimiterIndex = $rawOutput.LastIndexOf($metaToken)
            if ($delimiterIndex -lt 0) {
                return [PSCustomObject]@{
                    IPAddress = $ip
                    Success   = $false
                    Error     = '未找到 curl 元数据'
                }
            }

            $traceRaw = $rawOutput.Substring(0, $delimiterIndex)
            $metaRaw = $rawOutput.Substring($delimiterIndex + $metaToken.Length)
            $metaParts = $metaRaw.Split('|')
            $culture = [System.Globalization.CultureInfo]::InvariantCulture

            $timeConnect = $null
            $timeTotal = $null
            $speedDownload = $null

            if ($metaParts.Count -ge 1 -and [double]::TryParse($metaParts[0], [System.Globalization.NumberStyles]::Float, $culture, [ref]$timeConnect)) {}
            if ($metaParts.Count -ge 2 -and [double]::TryParse($metaParts[1], [System.Globalization.NumberStyles]::Float, $culture, [ref]$timeTotal)) {}
            if ($metaParts.Count -ge 3 -and [double]::TryParse($metaParts[2], [System.Globalization.NumberStyles]::Float, $culture, [ref]$speedDownload)) {}

            $traceData = @{}
            foreach ($line in ($traceRaw -split "`n")) {
                $clean = $line.Trim()
                if ([string]::IsNullOrWhiteSpace($clean)) { continue }
                $kv = $clean.Split('=')
                if ($kv.Count -ge 2) {
                    $key = $kv[0]
                    $value = ($kv[1..($kv.Count - 1)] -join '=')
                    $traceData[$key] = $value
                }
            }

            return [PSCustomObject]@{
                IPAddress     = $ip
                Success       = $true
                Trace         = $traceData
                TimeConnect   = $timeConnect
                TimeTotal     = $timeTotal
                SpeedDownload = $speedDownload
            }
        } -ArgumentList $ip, $CurlPath, $Domain, $Port
    }

    while ($jobs.Count -gt 0) {
        $finished = Wait-Job -Job $jobs -Any -Timeout 5
        if (-not $finished) { continue }
        $output = Receive-Job -Job $finished -ErrorAction SilentlyContinue
        if ($output) { $results.Add($output) }
        Remove-Job -Job $finished
        $jobs = $jobs | Where-Object { $_.Id -ne $finished.Id }
        $completed++
        Write-Progress -Activity 'RTT 信息采集' -Status "已完成 $completed/$total" -PercentComplete (($completed / $total) * 100)
    }

    Write-Progress -Activity 'RTT 信息采集' -Completed -Status '完成'

    $final = @()
    foreach ($item in $results.ToArray()) {
        if (-not $item.Success) {
            Write-Warn "RTT 测试失败: IP=$($item.IPAddress) Error=$($item.Error)"
            continue
        }

        $trace = $item.Trace
        $coloCode = if ($trace.ContainsKey('colo')) { $trace['colo'] } else { 'N/A' }
        $countryCode = if ($trace.ContainsKey('loc')) { $trace['loc'] } else { 'N/A' }
        $countryName = ConvertTo-RegionName -CountryCode $countryCode
        $coloDisplay = $coloCode
        if ($ColoMap -and $ColoMap.ContainsKey($coloCode)) {
            $entry = $ColoMap[$coloCode]
            $coloDisplay = "$coloCode - $($entry.City)"
        }

        $latencyMs = $null
        if ($item.TimeConnect) {
            $latencyMs = [math]::Round($item.TimeConnect * 1000, 2)
        }

        $final += [PSCustomObject]@{
            TransitIP    = $item.IPAddress
            TransitPort  = $Port
            ClientIP     = if ($trace.ContainsKey('ip')) { $trace['ip'] } else { '' }
            Country      = $countryName
            CountryCode  = $countryCode
            Colo         = $coloDisplay
            ColoCode     = $coloCode
            IPType       = Get-IPTypeFromTrace -TraceData $trace
            LatencyMs    = $latencyMs
            Trace        = $trace
            TimeTotal    = $item.TimeTotal
            SpeedSample  = $item.SpeedDownload
        }
    }

    return $final
}

function Test-Speed {
    <#
        .SYNOPSIS
            Optional throughput benchmarking using curl and a Cloudflare mirror.
        .OUTPUTS
            Hashtable keyed by TransitIP with speed metrics.
    #>
    param(
        [Parameter(Mandatory = $true)][pscustomobject[]]$RttResults,
        [Parameter(Mandatory = $true)][string]$CurlPath,
        [Parameter(Mandatory = $true)][string]$TargetDomain,
        [Parameter(Mandatory = $true)][string]$TargetUrl,
        [Parameter(Mandatory = $true)][int]$Port,
        [Parameter()][int]$Retry = 1,
        [Parameter()][int]$SampleSizeMB = 20
    )

    if (-not $RttResults -or $RttResults.Count -eq 0) {
        return @{}
    }

    Write-Info "启动速度测试，采样文件: $TargetUrl"
    $mapping = @{}
    $total = $RttResults.Count
    $index = 0

    foreach ($result in $RttResults) {
        $index++
        $ip = $result.TransitIP
        Write-Progress -Activity '速度测试' -Status "IP $index/$total" -PercentComplete (($index / $total) * 100)

        $success = $false
        $attempt = 0
        $metrics = $null

        while (-not $success -and $attempt -le $Retry) {
            $attempt++
            $metaToken = '__META__'
            $arguments = @(
                '--silent', '--show-error', '--location', '--connect-timeout', '8', '--max-time', '60',
                '--resolve', "$TargetDomain`:$Port`:$ip",
                '--range', "0-$([int]($SampleSizeMB * 1024 * 1024) - 1)",
                '--write-out', "$metaToken%{speed_download}|%{time_total}|%{size_download}",
                '--output', 'NUL',
                $TargetUrl
            )
            $rawOutput = & $CurlPath @arguments 2>&1
            $exitCode = $LASTEXITCODE

            if ($rawOutput -is [System.Array]) { $rawOutput = $rawOutput -join "`n" }

            if ($exitCode -ne 0) {
                Write-Warn "速度测试失败 (尝试 $attempt/$($Retry + 1)) IP=$ip"
                continue
            }

            $pos = $rawOutput.LastIndexOf($metaToken)
            if ($pos -lt 0) {
                continue
            }
            $meta = $rawOutput.Substring($pos + $metaToken.Length)
            $parts = $meta.Split('|')
            $culture = [System.Globalization.CultureInfo]::InvariantCulture

            $speed = 0.0
            $duration = 0.0
            $size = 0.0
            [double]::TryParse($parts[0], [System.Globalization.NumberStyles]::Float, $culture, [ref]$speed) | Out-Null
            if ($parts.Count -ge 2) { [double]::TryParse($parts[1], [System.Globalization.NumberStyles]::Float, $culture, [ref]$duration) | Out-Null }
            if ($parts.Count -ge 3) { [double]::TryParse($parts[2], [System.Globalization.NumberStyles]::Float, $culture, [ref]$size) | Out-Null }

            $success = $speed -gt 0
            if ($success) {
                $equivalentMbps = [math]::Round(($speed * 8) / 1MB, 2)
                $metrics = [PSCustomObject]@{
                    TransitIP       = $ip
                    SpeedBytes      = $speed
                    TimeTotal       = $duration
                    SizeBytes       = $size
                    EquivalentMbps  = $equivalentMbps
                    PeakMbps        = $equivalentMbps
                }
            }
        }

        if ($metrics) {
            $mapping[$ip] = $metrics
        }
    }

    Write-Progress -Activity '速度测试' -Completed -Status '完成'
    return $mapping
}

function Export-Results {
    <#
        .SYNOPSIS
            Exports base and speed-test CSV reports for a given ASN.
    #>
    param(
        [Parameter(Mandatory = $true)][string]$Asn,
        [Parameter(Mandatory = $true)][int]$Port,
        [Parameter(Mandatory = $true)][pscustomobject[]]$RttResults,
        [Parameter()][hashtable]$SpeedMap
    )

    if (-not $RttResults) {
        Write-Warn '没有可导出的 RTT 结果，跳过 CSV 生成。'
        return
    }

    $baseFile = Join-Path $Script:ScriptRoot ("AS{0}-{1}.csv" -f $Asn.Trim('A', 'S'), $Port)
    $export = @()
    foreach ($item in $RttResults) {
        $export += [PSCustomObject]@{
            '中转IP'   = $item.TransitIP
            '中转端口' = $item.TransitPort
            '回源IP'   = $item.ClientIP
            '国家'     = $item.Country
            '数据中心' = $item.Colo
            'IP类型'   = $item.IPType
            '网络延迟(ms)' = $item.LatencyMs
        }
    }

    $export | Export-Csv -Path $baseFile -Encoding UTF8 -NoTypeInformation
    Write-Info "$baseFile 已生成"

    if ($SpeedMap -and $SpeedMap.Count -gt 0) {
        $speedFile = Join-Path $Script:ScriptRoot ("AS{0}-{1}-速度.csv" -f $Asn.Trim('A', 'S'), $Port)
        $speedExport = @()
        foreach ($item in $RttResults) {
            $ip = $item.TransitIP
            $speedMetrics = $SpeedMap[$ip]
            if (-not $speedMetrics) { continue }
            $speedExport += [PSCustomObject]@{
                '中转IP'        = $ip
                '中转端口'      = $item.TransitPort
                '等效带宽(Mbps)' = $speedMetrics.EquivalentMbps
                '峰值速度(Mbps)' = $speedMetrics.PeakMbps
                '测试耗时(s)'    = $speedMetrics.TimeTotal
            }
        }

        if ($speedExport.Count -gt 0) {
            $speedExport | Export-Csv -Path $speedFile -Encoding UTF8 -NoTypeInformation
            Write-Info "$speedFile 已生成"
        }
    }
}

function Main {
    <#
        .SYNOPSIS
            Entry point orchestrating the Cloudflare scanning workflow.
    #>

    Write-Host '==============================================' -ForegroundColor DarkCyan
    Write-Host '  masscan Cloudflare 反代节点扫描 PowerShell 版 ' -ForegroundColor DarkCyan
    Write-Host '==============================================' -ForegroundColor DarkCyan

    $deps = Test-Dependencies
    $adapter = Get-NetworkAdapter

    if (-not $adapter) {
        Write-Warn '未选择网卡，某些 masscan 参数可能需要手动指定。'
    }

    $coloMap = Get-ColoData

    Write-Host "运行模式:" -ForegroundColor Green
    Write-Host "  [1] 单个 AS 号扫描" -ForegroundColor Green
    Write-Host "  [2] 批量 AS 列表扫描 (文件)" -ForegroundColor Green
    $mode = Read-Host '请选择运行模式 (默认 1)'
    if ([string]::IsNullOrWhiteSpace($mode)) { $mode = '1' }

    $portInput = Read-Host '请输入扫描端口 (默认 443, 多端口以逗号分隔)'
    if ([string]::IsNullOrWhiteSpace($portInput)) { $portInput = '443' }
    $firstPortToken = (($portInput -split ',')[0]).Trim()
    [int]$primaryPort = 443
    if (-not [int]::TryParse($firstPortToken, [ref]$primaryPort)) {
        Write-Warn '端口输入无法解析，使用默认 443'
        $primaryPort = 443
    }

    $rateInput = Read-Host '请设置 masscan PPS rate (默认 10000)'
    if ([string]::IsNullOrWhiteSpace($rateInput)) { $rateInput = '10000' }
    [int]$parsedRate = 0
    $rate = 10000
    if ([int]::TryParse($rateInput, [ref]$parsedRate)) {
        $rate = [math]::Max(1, $parsedRate)
    }
    else {
        Write-Warn '扫描速率输入非数字，使用默认 10000'
    }

    $coroutineInput = Read-Host '请输入 REAL IP 协程数 (默认 10, 范围 1-200)'
    if ([string]::IsNullOrWhiteSpace($coroutineInput)) { $coroutineInput = '10' }
    [int]$parsedCoroutine = 0
    $coroutines = 10
    if ([int]::TryParse($coroutineInput, [ref]$parsedCoroutine)) {
        $coroutines = [math]::Min(200, [math]::Max(1, $parsedCoroutine))
    }
    else {
        Write-Warn '协程数输入非数字，使用默认 10'
    }

    $rttConcurrencyInput = Read-Host '请输入 RTT 并发作业数 (1-20, 默认 10)'
    if ([string]::IsNullOrWhiteSpace($rttConcurrencyInput)) { $rttConcurrencyInput = '10' }
    [int]$parsedRtt = 0
    $rttConcurrency = 10
    if ([int]::TryParse($rttConcurrencyInput, [ref]$parsedRtt)) {
        $rttConcurrency = [math]::Min(20, [math]::Max(1, $parsedRtt))
    }
    else {
        Write-Warn 'RTT 并发输入非数字，使用默认 10'
    }

    $domain = Read-Host '请输入校验域名 (默认 www.cloudflare.com)'
    if ([string]::IsNullOrWhiteSpace($domain)) { $domain = 'www.cloudflare.com' }

    $enableSpeedTest = Read-Host '是否启用速度测试? (Y/N, 默认 N)'
    $speedTest = $false
    if ($enableSpeedTest -match '^(y|Y)') { $speedTest = $true }

    $speedUrl = 'https://download.cloudflare.com/archlinux/iso/latest/archlinux-x86_64.iso'
    $speedDomain = 'download.cloudflare.com'
    if ($speedTest) {
        $customUrl = Read-Host "速度测试下载 URL (默认 $speedUrl)"
        if (-not [string]::IsNullOrWhiteSpace($customUrl)) { $speedUrl = $customUrl }
        try {
            $uriObj = [System.Uri]::new($speedUrl)
            $speedDomain = $uriObj.Host
        }
        catch {
            Write-Warn '速度测试 URL 无法解析，使用默认配置。'
            $speedUrl = 'https://download.cloudflare.com/archlinux/iso/latest/archlinux-x86_64.iso'
            $speedDomain = 'download.cloudflare.com'
        }
    }

    $asnList = @()
    switch ($mode) {
        '2' {
            $filePath = Read-Host '请输入包含 AS 列表的文件路径'
            if (-not (Test-Path -LiteralPath $filePath)) {
                throw "列表文件不存在: $filePath"
            }
            $asnList = Get-Content -LiteralPath $filePath | Where-Object { -not [string]::IsNullOrWhiteSpace($_) }
        }
        Default {
            $asnInput = Read-Host '请输入 AS 号码 (默认 45102)'
            if ([string]::IsNullOrWhiteSpace($asnInput)) { $asnInput = '45102' }
            $asnList = @($asnInput)
        }
    }

    foreach ($asn in $asnList) {
        $stopwatch = [System.Diagnostics.Stopwatch]::StartNew()
        Write-Host "----------------------------------------------" -ForegroundColor DarkGray
        Write-Info "当前为 AS$asn 扫描流程"

        try {
            $asnData = Get-ASNData -Asn $asn
            if (-not $asnData.Targets -or $asnData.Targets.Count -eq 0) {
                Write-Warn "AS$asn 未获取到有效子网，跳过"
                continue
            }

            $masscanResult = Invoke-MasscanScan -MasscanPath $deps.MasscanPath -TargetFile $asnData.TargetFile -Ports $portInput -Rate $rate -AdapterInfo $adapter
            if ($masscanResult.OpenIpCount -eq 0) {
                Write-Warn "AS$asn 未扫描到开放端口"
                continue
            }

            Write-Info "开始检测 AS$asn REAL IP 有效性"
            $realIps = Test-RealIP -GoscanPath $deps.GoscanPath -CurlPath $deps.CurlPath -AllIpFile $masscanResult.AllIpFile -Domain $domain -Ports $portInput -Concurrency $coroutines
            if (-not $realIps -or $realIps.Count -eq 0) {
                Write-Warn "AS$asn 未获取到有效 REAL IP"
                continue
            }

            Write-Info "开始检测 AS$asn RTT 信息"
            $rttResults = Test-RTT -RealIpEntries $realIps -CurlPath $deps.CurlPath -Domain $domain -Port $primaryPort -Concurrency $rttConcurrency -ColoMap $coloMap
            if (-not $rttResults -or $rttResults.Count -eq 0) {
                Write-Warn 'RTT 检测无结果，跳过导出'
                continue
            }

            $speedMap = $null
            if ($speedTest) {
                $speedMap = Test-Speed -RttResults $rttResults -CurlPath $deps.CurlPath -TargetDomain $speedDomain -TargetUrl $speedUrl -Port $primaryPort
            }

            Export-Results -Asn $asnData.Asn -Port $primaryPort -RttResults $rttResults -SpeedMap $speedMap
        }
        catch {
            Write-ErrorMessage "AS$asn 处理异常: $($_.Exception.Message)"
        }
        finally {
            $stopwatch.Stop()
            Write-Info "AS$asn 耗时: $([math]::Round($stopwatch.Elapsed.TotalSeconds, 2)) 秒"
        }
    }

    Write-Host '任务完成，感谢使用 masscan-cf PowerShell 版。' -ForegroundColor DarkGreen
}

Main
