# =============================================================================
# Invoke-SecurityAudit.ps1
# Proyecto Final DevOps – Gestión de Parches y Auditoría de Seguridad
# Autor  : Equipo DevOps
# Versión: 1.0.0
# Fecha  : 2025
# =============================================================================
# Descripción:
#   Script principal que orquesta el flujo completo de auditoría:
#   1. Verifica parches de seguridad pendientes (PSWindowsUpdate)
#   2. Recopila eventos críticos del sistema de las últimas 24 horas
#   3. Genera un reporte HTML con los hallazgos
#   4. Envía una notificación vía Webhook (Slack / Discord)
# =============================================================================

#Requires -Version 5.1

[CmdletBinding()]
param(
    # Horas hacia atrás para buscar eventos (default 24)
    [int]$HorasAtras = 24,

    # Webhook URL para notificaciones (Slack o Discord)
    [string]$WebhookUrl = $env:AUDIT_WEBHOOK_URL,

    # Directorio de salida para el reporte HTML
    [string]$OutputDir = "$PSScriptRoot\..\output",

    # Si $true instala PSWindowsUpdate automáticamente si no está disponible
    [switch]$AutoInstallModule
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

# ---------------------------------------------------------------------------
# 0. INICIALIZACIÓN – rutas y variables globales
# ---------------------------------------------------------------------------
$script:StartTime  = Get-Date
$script:ReportDate = $script:StartTime.ToString("yyyy-MM-dd_HH-mm-ss")
$script:ReportFile = Join-Path $OutputDir "AuditReport_$($script:ReportDate).html"
$script:LogFile    = Join-Path $OutputDir "AuditLog_$($script:ReportDate).txt"

# Asegurar que el directorio de salida exista
if (-not (Test-Path $OutputDir)) {
    New-Item -ItemType Directory -Path $OutputDir -Force | Out-Null
}

# ---------------------------------------------------------------------------
# FUNCIÓN: Write-Log  – escribe en consola y en archivo de log simultáneamente
# ---------------------------------------------------------------------------
function Write-Log {
    param(
        [string]$Message,
        [ValidateSet("INFO","WARN","ERROR","SUCCESS")]
        [string]$Level = "INFO"
    )
    $timestamp = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
    $line = "[$timestamp][$Level] $Message"
    switch ($Level) {
        "INFO"    { Write-Host $line -ForegroundColor Cyan    }
        "WARN"    { Write-Host $line -ForegroundColor Yellow  }
        "ERROR"   { Write-Host $line -ForegroundColor Red     }
        "SUCCESS" { Write-Host $line -ForegroundColor Green   }
    }
    Add-Content -Path $script:LogFile -Value $line
}

# ---------------------------------------------------------------------------
# FUNCIÓN: Get-PendingPatches  – lista actualizaciones pendientes de Windows
# ---------------------------------------------------------------------------
function Get-PendingPatches {
    Write-Log "Buscando parches de seguridad pendientes..."

    # Instalar módulo si no existe y el switch fue indicado
    if (-not (Get-Module -ListAvailable -Name PSWindowsUpdate)) {
        if ($AutoInstallModule) {
            Write-Log "Instalando módulo PSWindowsUpdate..." "WARN"
            Install-Module -Name PSWindowsUpdate -Force -Scope CurrentUser
        } else {
            Write-Log "Módulo PSWindowsUpdate no disponible. Usando modo SIMULACIÓN." "WARN"
            # Modo simulación: retorna datos de ejemplo para demostración
            return @(
                [PSCustomObject]@{
                    KB          = "KB5034441"
                    Title       = "Actualización acumulativa para Windows 10 (Simulación)"
                    Size        = "245 MB"
                    Severity    = "Critical"
                    MsrcSeverity= "Critical"
                },
                [PSCustomObject]@{
                    KB          = "KB5033372"
                    Title       = "Actualización de seguridad para .NET Framework (Simulación)"
                    Size        = "87 MB"
                    Severity    = "Important"
                    MsrcSeverity= "Important"
                },
                [PSCustomObject]@{
                    KB          = "KB5031539"
                    Title       = "Windows Defender Antivirus – Actualización de definiciones (Simulación)"
                    Size        = "12 MB"
                    Severity    = "Low"
                    MsrcSeverity= "Low"
                }
            )
        }
    }

    try {
        Import-Module PSWindowsUpdate -ErrorAction Stop
        $updates = Get-WindowsUpdate -MicrosoftUpdate -AcceptAll -IgnoreReboot 2>$null
        Write-Log "Se encontraron $($updates.Count) actualizaciones pendientes." "SUCCESS"
        return $updates
    } catch {
        Write-Log "Error al consultar Windows Update: $_" "ERROR"
        throw
    }
}

# ---------------------------------------------------------------------------
# FUNCIÓN: Get-CriticalEvents  – extrae eventos críticos/errores recientes
# ---------------------------------------------------------------------------
function Get-CriticalEvents {
    param([int]$HorasAtras = 24)

    Write-Log "Recopilando eventos críticos de las últimas $HorasAtras horas..."

    $since = (Get-Date).AddHours(-$HorasAtras)

    $logs = @("System","Application","Security")
    $allEvents = @()

    foreach ($logName in $logs) {
        try {
            $events = Get-WinEvent -FilterHashtable @{
                LogName   = $logName
                Level     = 1, 2   # 1=Critical, 2=Error
                StartTime = $since
            } -ErrorAction SilentlyContinue

            if ($events) {
                $allEvents += $events | Select-Object `
                    TimeCreated,
                    @{N="Log";E={$logName}},
                    @{N="Level";E={ if ($_.Level -eq 1) {"Critical"} else {"Error"} }},
                    Id,
                    @{N="Source";E={$_.ProviderName}},
                    @{N="Message";E={ ($_.Message -split "`n")[0] -replace '"','' }}
            }
        } catch {
            Write-Log "No se pudo leer el log '$logName': $_" "WARN"
        }
    }

    $allEvents = $allEvents | Sort-Object TimeCreated -Descending | Select-Object -First 50

    Write-Log "Se encontraron $($allEvents.Count) eventos críticos/errores." `
        $(if ($allEvents.Count -gt 0) {"WARN"} else {"SUCCESS"})

    return $allEvents
}

# ---------------------------------------------------------------------------
# FUNCIÓN: New-HtmlReport  – genera el archivo HTML con los resultados
# ---------------------------------------------------------------------------
function New-HtmlReport {
    param(
        $Patches,
        $Events,
        [string]$OutFile,
        [int]$HorasAtras
    )

    Write-Log "Generando reporte HTML en: $OutFile"

    $hostname    = $env:COMPUTERNAME
    $os          = (Get-CimInstance Win32_OperatingSystem).Caption
    $reportDate  = (Get-Date).ToString("dd/MM/yyyy HH:mm:ss")
    $criticalCount = ($Patches | Where-Object { $_.MsrcSeverity -eq "Critical" }).Count
    $errorCount    = ($Events  | Where-Object { $_.Level -eq "Error"    }).Count
    $critEvtCount  = ($Events  | Where-Object { $_.Level -eq "Critical" }).Count

    # ── Status badge ──────────────────────────────────────────────────────
    if ($criticalCount -gt 0 -or $critEvtCount -gt 0) {
        $statusColor = "#e74c3c"; $statusText = "⚠ ATENCIÓN REQUERIDA"
    } elseif ($errorCount -gt 0 -or $Patches.Count -gt 0) {
        $statusColor = "#f39c12"; $statusText = "⚡ REVISAR"
    } else {
        $statusColor = "#27ae60"; $statusText = "✔ SISTEMA SALUDABLE"
    }

    # ── Construir filas de parches ─────────────────────────────────────────
    $patchRows = ""
    if ($Patches.Count -eq 0) {
        $patchRows = '<tr><td colspan="4" style="text-align:center;color:#27ae60;">Sin actualizaciones pendientes ✔</td></tr>'
    } else {
        foreach ($p in $Patches) {
            $sev = $p.MsrcSeverity
            $sevColor = switch ($sev) {
                "Critical"  { "#e74c3c" }
                "Important" { "#f39c12" }
                default     { "#3498db" }
            }
            $patchRows += "<tr>
                <td><code>$($p.KB)</code></td>
                <td>$($p.Title)</td>
                <td>$($p.Size)</td>
                <td><span style='background:$sevColor;color:#fff;padding:2px 8px;border-radius:4px;font-size:0.8em;'>$sev</span></td>
            </tr>`n"
        }
    }

    # ── Construir filas de eventos ─────────────────────────────────────────
    $eventRows = ""
    if ($Events.Count -eq 0) {
        $eventRows = '<tr><td colspan="6" style="text-align:center;color:#27ae60;">Sin eventos críticos/errores ✔</td></tr>'
    } else {
        foreach ($e in $Events) {
            $lvlColor = if ($e.Level -eq "Critical") {"#e74c3c"} else {"#e67e22"}
            $eventRows += "<tr>
                <td>$($e.TimeCreated.ToString('dd/MM HH:mm'))</td>
                <td>$($e.Log)</td>
                <td><span style='background:$lvlColor;color:#fff;padding:2px 6px;border-radius:4px;font-size:0.8em;'>$($e.Level)</span></td>
                <td>$($e.Id)</td>
                <td>$($e.Source)</td>
                <td style='max-width:300px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;'>$($e.Message)</td>
            </tr>`n"
        }
    }

    $html = @"
<!DOCTYPE html>
<html lang="es">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Reporte de Auditoría – $hostname</title>
<style>
  :root { --primary:#2c3e50; --accent:#2980b9; --bg:#f4f6f9; }
  * { box-sizing:border-box; margin:0; padding:0; }
  body { font-family:'Segoe UI',Arial,sans-serif; background:var(--bg); color:#333; }
  header { background:var(--primary); color:#fff; padding:24px 32px; }
  header h1 { font-size:1.6em; font-weight:700; }
  header p  { font-size:0.9em; opacity:.8; margin-top:4px; }
  .badge { display:inline-block; background:$statusColor; color:#fff;
           padding:6px 16px; border-radius:20px; font-weight:700;
           font-size:0.95em; margin-top:10px; }
  .container { max-width:1100px; margin:32px auto; padding:0 16px; }
  .cards { display:grid; grid-template-columns:repeat(auto-fit,minmax(180px,1fr)); gap:16px; margin-bottom:32px; }
  .card { background:#fff; border-radius:10px; padding:20px;
          box-shadow:0 2px 8px rgba(0,0,0,.08); text-align:center; }
  .card .num { font-size:2.2em; font-weight:800; color:var(--accent); }
  .card .lbl { font-size:0.85em; color:#666; margin-top:4px; }
  section { background:#fff; border-radius:10px; padding:24px;
            box-shadow:0 2px 8px rgba(0,0,0,.08); margin-bottom:24px; }
  section h2 { font-size:1.1em; color:var(--primary); margin-bottom:16px;
               padding-bottom:8px; border-bottom:2px solid var(--accent); }
  table { width:100%; border-collapse:collapse; font-size:0.88em; }
  th { background:var(--primary); color:#fff; padding:10px 12px; text-align:left; }
  td { padding:9px 12px; border-bottom:1px solid #eee; vertical-align:top; }
  tr:hover td { background:#f0f4ff; }
  footer { text-align:center; color:#aaa; font-size:0.8em; padding:24px; }
</style>
</head>
<body>
<header>
  <h1>🛡️ Reporte de Auditoría de Seguridad</h1>
  <p>Host: <strong>$hostname</strong> &nbsp;|&nbsp; SO: $os &nbsp;|&nbsp; Generado: $reportDate</p>
  <div class="badge">$statusText</div>
</header>

<div class="container">
  <div class="cards">
    <div class="card"><div class="num">$($Patches.Count)</div><div class="lbl">Parches Pendientes</div></div>
    <div class="card"><div class="num" style="color:#e74c3c;">$criticalCount</div><div class="lbl">Parches Críticos</div></div>
    <div class="card"><div class="num" style="color:#e67e22;">$errorCount</div><div class="lbl">Errores ($HorasAtras h)</div></div>
    <div class="card"><div class="num" style="color:#e74c3c;">$critEvtCount</div><div class="lbl">Eventos Críticos ($HorasAtras h)</div></div>
  </div>

  <section>
    <h2>📦 Actualizaciones de Seguridad Pendientes</h2>
    <table>
      <thead><tr><th>KB</th><th>Título</th><th>Tamaño</th><th>Severidad</th></tr></thead>
      <tbody>$patchRows</tbody>
    </table>
  </section>

  <section>
    <h2>🔴 Eventos Críticos / Errores (últimas $HorasAtras horas)</h2>
    <table>
      <thead><tr><th>Fecha</th><th>Log</th><th>Nivel</th><th>ID</th><th>Fuente</th><th>Mensaje</th></tr></thead>
      <tbody>$eventRows</tbody>
    </table>
  </section>
</div>

<footer>Generado automáticamente por Invoke-SecurityAudit.ps1 &nbsp;|&nbsp; DevOps – $reportDate</footer>
</body>
</html>
"@

    $html | Out-File -FilePath $OutFile -Encoding UTF8
    Write-Log "Reporte generado correctamente." "SUCCESS"
}

# ---------------------------------------------------------------------------
# FUNCIÓN: Send-WebhookNotification  – envía alerta a Slack / Discord
# ---------------------------------------------------------------------------
function Send-WebhookNotification {
    param(
        [string]$Url,
        $Patches,
        $Events,
        [string]$ReportPath
    )

    if ([string]::IsNullOrWhiteSpace($Url)) {
        Write-Log "No se configuró AUDIT_WEBHOOK_URL. Notificación omitida." "WARN"
        return
    }

    Write-Log "Enviando notificación al webhook..."

    $criticalPatches = ($Patches | Where-Object { $_.MsrcSeverity -eq "Critical" }).Count
    $criticalEvents  = ($Events  | Where-Object { $_.Level -eq "Critical"         }).Count
    $errorEvents     = ($Events  | Where-Object { $_.Level -eq "Error"            }).Count

    $emoji  = if ($criticalPatches -gt 0 -or $criticalEvents -gt 0) {"🚨"} else {"✅"}
    $status = if ($criticalPatches -gt 0 -or $criticalEvents -gt 0) {"ATENCIÓN REQUERIDA"} else {"Sistema Saludable"}

    $message = "$emoji *Auditoría DevOps – $($env:COMPUTERNAME)*`n" +
               "Estado: *$status*`n" +
               "• Parches pendientes: $($Patches.Count) ($criticalPatches críticos)`n" +
               "• Errores (24h): $errorEvents  |  Críticos: $criticalEvents`n" +
               "• Reporte: ``$(Split-Path $ReportPath -Leaf)``"

    # Formato compatible con Slack y Discord (ambos usan "text")
    $body = @{ text = $message } | ConvertTo-Json -Depth 3

    try {
        $response = Invoke-RestMethod -Uri $Url -Method Post `
            -ContentType "application/json" -Body $body
        Write-Log "Notificación enviada correctamente." "SUCCESS"
    } catch {
        Write-Log "Error al enviar notificación: $_" "ERROR"
        # No se relanza: el fallo de notificación no debe detener el script
    }
}

# ===========================================================================
# FLUJO PRINCIPAL
# ===========================================================================
try {
    Write-Log "===== INICIO DE AUDITORÍA DE SEGURIDAD ====="
    Write-Log "Host: $env:COMPUTERNAME | Usuario: $env:USERNAME"

    # 1. Parches pendientes
    $patches = Get-PendingPatches

    # 2. Eventos críticos
    $events = Get-CriticalEvents -HorasAtras $HorasAtras

    # 3. Reporte HTML
    New-HtmlReport -Patches $patches -Events $events `
        -OutFile $script:ReportFile -HorasAtras $HorasAtras

    # 4. Notificación webhook
    Send-WebhookNotification -Url $WebhookUrl `
        -Patches $patches -Events $events `
        -ReportPath $script:ReportFile

    $elapsed = ((Get-Date) - $script:StartTime).TotalSeconds
    Write-Log "===== AUDITORÍA COMPLETADA en $([math]::Round($elapsed,1))s =====" "SUCCESS"
    Write-Log "Reporte disponible en: $script:ReportFile" "SUCCESS"

    exit 0

} catch {
    Write-Log "ERROR FATAL durante la auditoría: $_" "ERROR"
    Write-Log "StackTrace: $($_.ScriptStackTrace)" "ERROR"

    # Intentar notificar el fallo
    if (-not [string]::IsNullOrWhiteSpace($WebhookUrl)) {
        $failBody = @{ text = "🚨 *ERROR* en Auditoría DevOps ($env:COMPUTERNAME): $_" } | ConvertTo-Json
        try {
            Invoke-RestMethod -Uri $WebhookUrl -Method Post `
                -ContentType "application/json" -Body $failBody -ErrorAction SilentlyContinue
        } catch {}
    }

    exit 1
}
