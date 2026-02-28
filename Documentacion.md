# Documentacion Tecnica - Nyx Monitor

## 1. Resumen del proyecto

Nyx Monitor es una aplicacion desktop para Windows construida con Tauri, React y Rust para monitorizar procesos, evaluar confianza y detectar comportamiento sospechoso con telemetria en tiempo real.

Este documento refleja el estado actual depurado del proyecto y sustituye documentacion historica de etapas anteriores.

## 2. Objetivo funcional

El objetivo del sistema es dar visibilidad operativa de lo que ocurre en el PC en todo momento:

- que procesos se ejecutan y su arbol padre/hijo
- consumo de CPU/GPU/memoria por proceso
- inventario de software instalado
- procesos de inicio de sistema
- timeline de eventos de seguridad/actividad
- sistema de alertas y respuesta operativa

## 3. Stack y arquitectura

### 3.1 Stack

- Desktop shell: `Tauri 2`
- Frontend: `React 18 + TypeScript + Vite`
- Backend: `Rust`
- Graficas: `Recharts`
- Persistencia:
  - JSON: alertas, entidades conocidas, acciones de respuesta
  - SQLite: timeline de eventos (`events.db`)

### 3.2 Estructura principal

- `src/`
  - `App.tsx`: orquestacion de tabs y dialogos
  - `hooks/useMonitoringData.ts`: polling, cargas y mutaciones de datos
  - `components/`: tablas/paneles por dominio (Processes, Threats, Health, Response, etc.)
  - `lib/api.ts`: cliente de comandos Tauri
  - `styles/global.css`: sistema visual
- `src-tauri/src/`
  - `main.rs`: comandos Tauri y bootstrap
  - `monitoring/`: colectores de proceso, red, GPU, registro, startup, programas, confianza
  - `detection/mod.rs`: heuristicas y scoring/veredicto
  - `app_state.rs`: estado runtime, dedupe/supresion de alertas, overrides, politicas
  - `storage/mod.rs`: stores JSON y SQLite
  - `models.rs`: contratos de datos compartidos

## 4. Modulos funcionales actuales

### 4.1 Procesos (tab Processes)

- `Process Tree` con expandir/contraer y busqueda por nombre/ruta/PID.
- `Live Processes` con:
  - estado running y nivel de confianza
  - CPU, GPU, memoria, inicio, score y veredicto
  - pausa de refresco y velocidad de actualizacion
- Click en proceso abre un dialogo con:
  - datos del proceso (PID, PPID, ruta, hash SHA-256)
  - acciones externas (VT por hash/nombre, Google por nombre)
  - cambio de confianza y etiqueta personalizada
  - apertura de carpeta del proceso y del proceso padre

### 4.2 Threats

- Lista de procesos bajo revision (`risk != legitimate`).
- Orden por score/riesgo.
- Evidencias visibles por proceso.

### 4.3 Alerts

- Alertas activas por deteccion/CPU/respuesta.
- Borrado individual y masivo.
- Supresion temporal de alertas borradas para evitar reaparicion inmediata.

### 4.4 Installed programs

- Inventario de programas instalados desde registro de Windows.
- Clasificacion por confianza (`trusted` y `unknown`).
- Override manual de confianza/etiqueta por programa.
- Apertura de ruta desde UI.

### 4.5 Startup, History, Timeline, Health y Response

- `Startup`: entradas de arranque (run keys + startup folders).
- `History`: uso historico de apps (primera/ultima vez, lanzamientos, pico CPU).
- `Timeline`: stream de eventos de proceso/red/registro/respuesta.
- `Health`: estado de sensores y tiempos del loop.
- `Response`: politica (audit/constrain), umbrales y acciones manuales.

## 5. Deteccion y reduccion de falsos positivos

Se aplicaron ajustes importantes para reducir falsos positivos observados (ej. `ChatGPT.exe`, `nyx-monitor.exe`):

- veredicto final endurecido y contextual:
  - no depende solo de score bruto
  - considera nivel base, confianza, correlacion y si es proceso interno
- correlacion menos agresiva y con cap de impacto
- menor peso de `cpu_spike` como indicador aislado
- procesos internos de Nyx se marcan como `Trusted` y no generan alertas propias
- aumento de cobertura de comprobacion de firma por ciclo
- trust baseline ampliado con publishers y ejecutables conocidos
- nuevo campo explicable `risk_factors` para mostrar por que se clasifico un proceso

## 6. Persistencia y estado

Archivos persistidos en `app_data_dir` de Tauri:

- `alerts.json`
- `known_entities.json`
- `events.db`
- `response_actions.json`

Detalles relevantes:

- overrides de confianza/etiqueta por proceso y programa
- sincronizacion de aliases por nombre/ruta para consistencia
- historial de alertas con deduplicacion y supresion temporal tras borrado

## 7. Comandos Tauri expuestos (resumen)

- lectura:
  - `get_process_tree`
  - `get_process_metrics`
  - `get_installed_programs`
  - `get_startup_processes`
  - `get_app_usage_history`
  - `get_active_alerts`
  - `get_alert_history`
  - `get_event_timeline`
  - `get_sensor_health`
  - `get_performance_stats`
  - `get_response_policy`
  - `get_response_actions`
- mutacion/acciones:
  - `set_detection_profile`
  - `set_cpu_spike_threshold`
  - `set_response_policy`
  - `run_response_action`
  - `delete_alert`
  - `delete_all_alerts`
  - `set_process_trust_override`
  - `add_known_program`
  - `open_path_in_explorer`
  - `open_process_folder_by_pid`
  - `open_url_in_browser`
  - `get_file_sha256`

## 8. Ejecucion y build

### 8.1 Requisitos locales

- Windows 10/11
- Node.js 20+
- Rust stable (`cargo`)
- Visual Studio Build Tools (MSVC + Windows SDK)
- WebView2 Runtime

### 8.2 Desarrollo

```powershell
npm install
npm run tauri dev
```

### 8.3 Build de distribucion

```powershell
npm run tauri build
```

### 8.4 Release publico automatizado

Se agrego workflow de GitHub Actions para Windows:

- `.github/workflows/release-windows.yml`

Funcionamiento:

1. push de tag `v*`
2. build de instalador `NSIS .exe`
3. publicacion automatica en GitHub Releases

Ejemplo:

```powershell
git tag v0.1.1
git push origin v0.1.1
```

## 9. Problemas comunes y solucion

### 9.1 `cargo metadata ... program not found`

Falta `cargo` en PATH o no esta instalado.

Accion:

1. instalar Rust (`rustup`)
2. abrir terminal nueva
3. validar con `cargo --version`

### 9.2 `link.exe` o `kernel32.lib` no encontrado

Toolchain C++/SDK incompleto.

Accion:

1. instalar Build Tools C++ + SDK
2. ejecutar `npm run tauri dev` usando wrapper de proyecto

## 10. Estado actual de calidad

- Frontend: compila (`npm run build`)
- Backend: requiere entorno Rust local activo para comprobar `cargo check`/`tauri build`
- Documentacion alineada con nombre y arquitectura actual (`Nyx Monitor`)

## 11. Limites actuales y siguientes pasos

Limites:

- motor heuristico, no equivalente a un EDR enterprise
- aun puede haber falsos positivos residuales en entornos muy ruidosos

Siguientes pasos recomendados:

1. baseline de comportamiento por host (fase de aprendizaje)
2. reputacion por hash con cache local y politicas de expiracion
3. reglas por firma/editor mas granulares
4. test automaticos de regresion para scoring y overrides
