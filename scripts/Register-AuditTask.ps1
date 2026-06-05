# =============================================================================
# Register-AuditTask.ps1
# Registra la tarea programada en el Programador de Tareas de Windows
# DEBE ejecutarse como Administrador
# =============================================================================

#Requires -RunAsAdministrator

[CmdletBinding()]
param(
    # Hora de ejecución diaria (formato HH:mm)
    [string]$HoraEjecucion = "07:00",

    # Webhook opcional (puede dejarse vacío y configurarse luego como variable de entorno)
    [string]$WebhookUrl = ""
)

$TaskName   = "DevOps-SecurityAudit"
$ScriptPath = Join-Path $PSScriptRoot "Invoke-SecurityAudit.ps1"

Write-Host "[INFO] Registrando tarea programada: $TaskName" -ForegroundColor Cyan

# Eliminar tarea previa si existe
if (Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue) {
    Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false
    Write-Host "[INFO] Tarea anterior eliminada." -ForegroundColor Yellow
}

# Configurar la acción (ejecutar el script principal)
$action = New-ScheduledTaskAction `
    -Execute "powershell.exe" `
    -Argument "-NonInteractive -NoProfile -ExecutionPolicy Bypass -File `"$ScriptPath`" -AutoInstallModule" `
    -WorkingDirectory $PSScriptRoot

# Disparador: diariamente a la hora configurada
$trigger = New-ScheduledTaskTrigger -Daily -At $HoraEjecucion

# Configuración: ejecutar aunque no haya usuario conectado, con privilegios elevados
$settings = New-ScheduledTaskSettingsSet `
    -ExecutionTimeLimit (New-TimeSpan -Minutes 30) `
    -StartWhenAvailable `
    -RunOnlyIfNetworkAvailable

$principal = New-ScheduledTaskPrincipal `
    -UserId "SYSTEM" `
    -LogonType ServiceAccount `
    -RunLevel Highest

# Si se pasó webhook, configurarlo como variable de entorno del sistema
if (-not [string]::IsNullOrWhiteSpace($WebhookUrl)) {
    [System.Environment]::SetEnvironmentVariable(
        "AUDIT_WEBHOOK_URL", $WebhookUrl, "Machine"
    )
    Write-Host "[INFO] Variable de entorno AUDIT_WEBHOOK_URL configurada." -ForegroundColor Green
}

Register-ScheduledTask `
    -TaskName  $TaskName `
    -Action    $action `
    -Trigger   $trigger `
    -Settings  $settings `
    -Principal $principal `
    -Description "Auditoría diaria de seguridad Windows – Proyecto DevOps" | Out-Null

Write-Host "[SUCCESS] Tarea '$TaskName' registrada para ejecutarse a las $HoraEjecucion diariamente." `
    -ForegroundColor Green
Write-Host "[INFO] Para ejecutarla ahora: Start-ScheduledTask -TaskName '$TaskName'" -ForegroundColor Cyan
