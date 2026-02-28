# Nyx Monitor

Nyx Monitor es una aplicacion de escritorio para Windows enfocada en monitorizacion de procesos en tiempo real, confianza de procesos/programas y deteccion de actividad sospechosa.

## Funcionalidades principales

- Arbol de procesos (PID/PPID) y lista de procesos activos.
- Uso de CPU y GPU por proceso.
- Clasificacion de confianza (`trusted`, `windows_native`, `unknown`).
- Alertas por comportamientos sospechosos y picos de CPU.
- Inventario de programas instalados y procesos de inicio.
- Busqueda de procesos/programas y acceso rapido a VirusTotal.
- Personalizacion manual de confianza y etiqueta por proceso.

## Stack

- Frontend: React + TypeScript + Vite
- Desktop runtime: Tauri 2
- Backend: Rust (`sysinfo`, `tokio`, `serde`)
- Graficas: Recharts

## Requisitos

- Windows 10/11
- Node.js 20+
- Rust stable (`rustup`, `cargo`)
- Visual Studio Build Tools (MSVC + Windows SDK)
- WebView2 Runtime

## Ejecutar en local

```powershell
npm install
npm run tauri dev
```

## Build de instalador

```powershell
npm run tauri build
```

Artefactos generados:

- `src-tauri/target/release/bundle/msi/`
- `src-tauri/target/release/bundle/nsis/`

## Scripts disponibles

- `npm run dev`: frontend con Vite
- `npm run build`: build de frontend
- `npm run preview`: preview de frontend
- `npm run tauri dev`: app de escritorio en desarrollo
- `npm run tauri build`: build instalable

## Estructura del proyecto

- `src/`: UI React, componentes y hooks
- `src-tauri/src/`: backend Rust (coleccion, deteccion, almacenamiento)
- `src-tauri/icons/`: iconos de aplicacion
- `scripts/tauri-wrapper.ps1`: wrapper para ejecutar Tauri en entorno Windows

## Estado actual

- Proyecto orientado a Windows.
- No hay pipeline de tests automatizados definido en scripts por ahora.

