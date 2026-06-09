# 🛡️ DevOps – Gestión de Parches y Auditoría de Seguridad

Proyecto Final – Desarrollo de Sistemas de Información | DevOps  
Docente: Rildo M. Tapia Pacheco

---

## 📋 Descripción

Sistema automatizado que audita la seguridad de equipos Windows, detecta parches faltantes,
recopila eventos críticos del sistema y genera reportes HTML con notificaciones automáticas
vía Webhook (Slack / Discord).

## 🗂️ Estructura del repositorio

```
proyecto_auditoria/
├── scripts/
│   ├── Invoke-SecurityAudit.ps1   # Script principal de auditoría
│   └── Register-AuditTask.ps1     # Registra la tarea programada en Windows
├── output/                        # Reportes HTML generados (gitignored)
├── docs/
│   └── Documentacion_Proyecto.docx
└── README.md
```

## ⚙️ Requisitos

- Windows 10 / Windows Server 2016 o superior
- PowerShell 5.1 o superior
- Acceso a Internet (para Windows Update)
- Permisos de Administrador (para la tarea programada)

## 🚀 Instalación rápida

### 1. Clonar el repositorio
```powershell
git clone https://github.com/20241d020-hue/devops-security-audit.git
cd devops-security-audit
```

### 2. Instalar módulo PSWindowsUpdate
```powershell
Install-Module -Name PSWindowsUpdate -Force -Scope CurrentUser
```

### 3. Configurar Webhook (opcional)
```powershell
# Variable de entorno para Slack o Discord
$env:AUDIT_WEBHOOK_URL = "https://hooks.slack.com/services/TU_WEBHOOK"
```

### 4. Registrar tarea programada (como Administrador)
```powershell
.\scripts\Register-AuditTask.ps1 -HoraEjecucion "07:00" -WebhookUrl "https://hooks.slack.com/..."
```

### 5. Ejecutar manualmente (prueba)
```powershell
.\scripts\Invoke-SecurityAudit.ps1 -AutoInstallModule
```

## 🔄 Flujo de ejecución

```
Programador de Tareas (07:00)
         │
         ▼
Invoke-SecurityAudit.ps1
         │
         ├─► Get-PendingPatches()   → PSWindowsUpdate
         ├─► Get-CriticalEvents()   → Get-WinEvent (System, Application, Security)
         ├─► New-HtmlReport()       → output/AuditReport_YYYY-MM-DD.html
         └─► Send-WebhookNotification() → Slack / Discord
```

## 📊 Ejemplo de salida

El script genera un reporte HTML en `output/` con:
- Resumen ejecutivo (tarjetas con contadores)
- Tabla de parches pendientes con severidad color-coded
- Tabla de eventos críticos/errores de las últimas 24 horas
- Timestamp y nombre del equipo

## 🧪 Modo simulación

Si `PSWindowsUpdate` no está instalado y no se pasa `-AutoInstallModule`,
el script corre en modo simulación con datos de ejemplo para demostración.

```powershell
# Ejecutar en modo simulación (sin necesidad de módulo externo)
.\scripts\Invoke-SecurityAudit.ps1
```

## 📁 Historial de commits sugerido

```
feat: estructura inicial del proyecto
feat: función Get-PendingPatches con modo simulación
feat: función Get-CriticalEvents con Get-WinEvent
feat: generación de reporte HTML responsivo
feat: notificación via Webhook (Slack/Discord)
feat: manejo de errores y logging centralizado
feat: script de registro de tarea programada
docs: documentación y README
```

## 👥 Autores
Josept Enrrique Turpo Yancce
Proyecto Final DevOps – 2025
