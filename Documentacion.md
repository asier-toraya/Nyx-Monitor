# Documentacion del Proyecto P-Control

## 1. Objetivo alcanzado

Se construyo una aplicacion de escritorio para Windows llamada **P-Control** con:

- Monitoreo de procesos en tiempo real.
- Estructura de arbol padre/hijo de procesos.
- Metricas por proceso: CPU, GPU y memoria.
- Clasificacion de riesgo por proceso: `legitimate`, `unknown`, `suspicious`.
- Centro de alertas (incluye picos de CPU y reglas de comportamiento sospechoso).
- Inventario de programas instalados del sistema.
- Interfaz grafica moderna y responsive.
- Generacion de instaladores (`.msi` y `.exe`).

## 2. Stack final implementado

- **Desktop shell**: Tauri 2
- **Backend**: Rust
- **Frontend**: React + TypeScript + Vite
- **Graficas**: Recharts
- **Estado UI**: estado local en React (estructura modular)
- **Persistencia alertas**: JSON local (store propio)

## 3. Estructura creada

Se creo el proyecto desde cero en:

`C:\Users\asier\Documents\Proyectos\P-Control`

Carpetas principales:

- `src/` (frontend)
- `src-tauri/` (backend Rust + configuracion Tauri)
- `scripts/` (automatizacion entorno local)

## 4. Funcionalidad implementada

### 4.1 Backend (Rust/Tauri)

Archivos clave:

- `src-tauri/src/main.rs`
- `src-tauri/src/models.rs`
- `src-tauri/src/app_state.rs`
- `src-tauri/src/detection/mod.rs`
- `src-tauri/src/monitoring/process_collector.rs`
- `src-tauri/src/monitoring/gpu_collector.rs`
- `src-tauri/src/monitoring/programs.rs`
- `src-tauri/src/storage/mod.rs`

Capacidades implementadas:

- Snapshot periodico de procesos (`sysinfo`).
- Reconstruccion de arbol por `pid/ppid`.
- Lectura de uso GPU por proceso via `Get-Counter \GPU Engine(*)\Utilization Percentage`.
- Lectura de programas instalados desde registro:
  - `HKLM\...\Uninstall`
  - `HKLM\SOFTWARE\WOW6432Node\...\Uninstall`
  - `HKCU\...\Uninstall`
- Verificacion de firma de binarios con `Get-AuthenticodeSignature`.
- Motor de scoring conservador basado en reglas.
- Deteccion de picos sostenidos de CPU con baseline local.
- Emision y deduplicacion de alertas.
- Persistencia de alertas en disco.
- Comandos Tauri expuestos a UI:
  - `get_process_tree`
  - `get_process_metrics`
  - `get_installed_programs`
  - `get_active_alerts`
  - `get_alert_history`
  - `ack_alert`
  - `set_detection_profile`
  - `set_cpu_spike_threshold`

### 4.2 Frontend (React)

Archivos clave:

- `src/App.tsx`
- `src/components/*`
- `src/lib/api.ts`
- `src/styles/global.css`
- `src/types.ts`

Vistas implementadas:

- **Overview**: KPIs + grafica de carga + alertas.
- **Processes**: arbol de procesos + tabla de procesos activos.
- **Alerts**: listado y acknowledge.
- **Installed**: listado filtrable de software instalado.

UI:

- Tema claro con identidad visual definida.
- Responsive para desktop y mobile.
- Estilos modulares con variables CSS.

## 5. Cambios de configuracion y build

Archivos:

- `package.json`
- `tsconfig.json`
- `vite.config.ts`
- `src-tauri/Cargo.toml`
- `src-tauri/tauri.conf.json`
- `src-tauri/capabilities/default.json`
- `.gitignore`
- `README.md`

Se agrego icono de aplicacion:

- `src-tauri/icons/icon.ico`

Se configuro bundle Tauri con icono explicito:

- `"bundle.icon": ["icons/icon.ico"]`

## 6. Depuracion realizada (incidencias y solucion)

### 6.1 `cargo` no encontrado

Error inicial:

- `failed to run 'cargo metadata' ... program not found`

Solucion:

- Instalacion de Rust (`rustup/cargo`) con `winget`.

### 6.2 `link.exe` no encontrado

Error:

- `linker link.exe not found`

Solucion:

- Instalacion de **Visual Studio Build Tools 2022** con toolset C++.
- Verificacion manual de `link.exe` en:
  - `C:\BuildTools\VC\Tools\MSVC\14.44.35207\bin\Hostx86\x64\link.exe`

### 6.3 `kernel32.lib` no encontrado

Error:

- `LNK1181: cannot open input file 'kernel32.lib'`

Causa:

- Variables de entorno de compilacion (`LIB/INCLUDE/PATH`) no quedaban consistentes en la sesion.

Solucion:

- Configuracion explicita de `PATH`, `LIB`, `INCLUDE` para MSVC + Windows SDK.
- Automatizacion definitiva via script wrapper.

### 6.4 Fallos de Tauri build por recursos

Errores:

- `icons/icon.ico not found`
- `.ico parse failed`
- `Couldn't find a .ico icon`

Solucion:

- Creacion de `src-tauri/icons/icon.ico` valido.
- Configuracion de icono en `tauri.conf.json`.

### 6.5 Errores de codigo Rust

Error:

- `cannot find type HKEY in this scope`

Solucion:

- Import correcto: `use winreg::{enums::*, HKEY, RegKey};`

### 6.6 Colisiones de proceso en desarrollo

Incidencias:

- Puerto `1420` ocupado por Vite.
- `p-control.exe` bloqueado en recompilacion.

Solucion:

- Cierre de procesos residuales y relanzamiento limpio.

## 7. Automatizacion agregada

Se creo:

- `scripts/tauri-wrapper.ps1`

Funcion:

- Detecta automaticamente ruta de MSVC y SDK.
- Configura `PATH`, `LIB`, `INCLUDE`.
- Ejecuta `tauri` con el entorno correcto.

Se ajusto `package.json`:

- `tauri:raw` -> comando directo.
- `tauri` -> wrapper PowerShell.

Resultado: ya no hace falta exportar variables manualmente en cada ejecucion.

## 8. Estado final validado

### 8.1 Desarrollo

Comando validado:

```powershell
npm run tauri dev
```

Compila y ejecuta la app.

### 8.2 Build instalable

Comando validado:

```powershell
npm run tauri build
```

Artefactos generados:

- `C:\Users\asier\Documents\Proyectos\P-Control\src-tauri\target\release\bundle\msi\P-Control_0.1.0_x64_en-US.msi`
- `C:\Users\asier\Documents\Proyectos\P-Control\src-tauri\target\release\bundle\nsis\P-Control_0.1.0_x64-setup.exe`

## 9. Ajustes tecnicos adicionales realizados

- Correccion del payload de `ack_alert` (`alert_id`).
- Persistencia de alertas en almacenamiento local.
- Deduplicacion temporal de alertas activas.
- Definicion de tipos compartidos TS/Rust para sincronia backend-frontend.
- README actualizado con requisitos y flujo de ejecucion/build.

## 10. Estado del proyecto

**Operativo en local, compilable y empaquetable**, con funcionalidades base de monitorizacion, analisis y alertado implementadas.

## 11. Iteracion de mejoras (UI Obsidian + confianza + nuevas pestanas)

En esta iteracion se aplicaron cambios solicitados en estetica y funcionalidad.

### 11.1 Estetica y UX

- Rediseno visual inspirado en Obsidian (base oscura, superficies tipo panel).
- Modo claro/oscuro con switch en cabecera y persistencia en `localStorage`.
- Cards y paneles con esquinas casi rectas (`border-radius` bajo).
- Refinamiento responsive para desktop y mobile.

Archivos principales:

- `src/styles/global.css`
- `src/App.tsx`

### 11.2 Procesos: organizacion y confianza

Se agrego clasificacion de confianza por proceso:

- `windows_native`
- `trusted`
- `unknown`

Y se reorganizo la tabla de procesos por grupos:

- **Legitimos (Windows)**
- **Conocidos (Fuentes de confianza)**
- **Desconocidos**

Tambien se agregaron:

- Indicador rapido de confianza con circulo verde/amarillo/rojo en `Running`.
- Mas detalle en filas (PID/PPID, inicio, score de riesgo, ruta).
- Click sobre proceso (tabla y arbol) para abrir ubicacion en el Explorador.

Archivos principales:

- `src/components/ProcessTable.tsx`
- `src/components/ProcessTree.tsx`
- `src/components/TrustIndicator.tsx`
- `src/lib/format.ts`
- `src/lib/api.ts`

### 11.3 Control de refresco en Running processes

Se implemento:

- Boton de pausar/reanudar refresco de procesos.
- Selector de velocidad:
  - `Muy baja`
  - `Baja`
  - `Normal`
  - `Rapida`

Archivo principal:

- `src/App.tsx`

### 11.4 Installed programs (renombre + subpestanas)

Cambios aplicados:

- Renombre de pestana principal a **Installed programs**.
- Subpestanas internas por confianza:
  - `Nativos de Windows`
  - `Conocidos`
  - `Desconocidos`
- Indicador de confianza por programa (verde/amarillo/rojo).
- Click en programa para abrir ubicacion en Explorador.

Se amplian datos de backend con:

- `install_location`
- `executable_path`
- `trust_level`

Archivos principales:

- `src/components/InstalledProgramsTable.tsx`
- `src-tauri/src/monitoring/programs.rs`
- `src-tauri/src/models.rs`

### 11.5 Nuevas pestanas: Startup y App history

Nuevas vistas agregadas:

- **Startup**: elementos de arranque del sistema (Run keys + startup folders).
- **App history**: historial de uso en la sesion actual (primer/ultimo visto, conteo de lanzamientos, CPU pico).

Archivos principales:

- `src/components/StartupProcessesTable.tsx`
- `src/components/AppUsageHistoryTable.tsx`
- `src-tauri/src/monitoring/startup.rs`
- `src-tauri/src/app_state.rs`
- `src-tauri/src/main.rs`
- `src/lib/api.ts`
- `src/types.ts`

### 11.6 Alertas de P-Control ignoradas

Se aplica filtro para no generar alertas sobre el propio proceso de la aplicacion (`p-control`).

Archivo principal:

- `src-tauri/src/monitoring/mod.rs`

### 11.7 Nuevos comandos Tauri expuestos

- `get_startup_processes`
- `get_app_usage_history`
- `open_path_in_explorer`

Archivo:

- `src-tauri/src/main.rs`

### 11.8 Validacion tras cambios

Comandos ejecutados y validados:

```powershell
npm run build
npm run tauri -- build --debug
```

Resultado:

- Frontend compila correctamente.
- Backend compila correctamente.
- Bundles generados correctamente (`MSI` y `NSIS`).

## 12. Iteracion de mejoras (busqueda, VirusTotal, lista blanca y alertas)

Se implementaron las funcionalidades adicionales solicitadas para procesos, programas y alertas.

### 12.1 Buscadores en pestana Processes

- Se agrego buscador en **Running Processes** (nombre, ruta, PID y PPID).
- Se agrego buscador en **Process Tree** (nombre, ruta y PID).
- El filtrado del arbol conserva ramas con coincidencias hijas.

Archivos:

- `src/components/ProcessTable.tsx`
- `src/components/ProcessTree.tsx`

### 12.2 Enlace rapido a VirusTotal

- En procesos/programas con confianza `unknown` se muestra un boton `VT` junto al nombre.
- El enlace abre busqueda en VirusTotal por nombre de proceso/programa.

Archivos:

- `src/components/ProcessTable.tsx`
- `src/components/ProcessTree.tsx`
- `src/components/InstalledProgramsTable.tsx`
- `src/styles/global.css`

### 12.3 Lista blanca de conocidos (persistente)

Se creo un registro persistente para marcar elementos desconocidos como conocidos:

- Click sobre indicador rojo (`unknown`) abre menu.
- Opcion:
  - `Anadir a procesos conocidos`
  - `Anadir a programas conocidos`
- Se solicita un nombre de etiqueta.
- Esa etiqueta se muestra en UI en lugar de `Unknown`.
- Se persiste en:
  - `known_entities.json` dentro de `app_data_dir` de Tauri.

Se aplica en runtime para:

- Procesos en ejecucion y Process Tree.
- Installed programs.

Archivos:

- `src/components/TrustIndicator.tsx`
- `src/lib/api.ts`
- `src/App.tsx`
- `src-tauri/src/models.rs`
- `src-tauri/src/app_state.rs`
- `src-tauri/src/storage/mod.rs`
- `src-tauri/src/monitoring/trust.rs`
- `src-tauri/src/monitoring/mod.rs`
- `src-tauri/src/main.rs`

### 12.4 Borrado de alertas

- Se agrego boton `Delete` en cada alerta.
- El borrado elimina la alerta del store persistente.

Archivos:

- `src/components/AlertsPanel.tsx`
- `src/lib/api.ts`
- `src-tauri/src/storage/mod.rs`
- `src-tauri/src/app_state.rs`
- `src-tauri/src/main.rs`

### 12.5 Compactado del Process Tree

- Se sustituyo el render anterior por nodos con flecha de expandir/contraer.
- Permite compactar ramas padre para evitar listas largas.

Archivos:

- `src/components/ProcessTree.tsx`
- `src/styles/global.css`

### 12.6 Comandos Tauri nuevos de esta iteracion

- `delete_alert`
- `add_known_process`
- `add_known_program`

### 12.7 Validacion

Comandos ejecutados:

```powershell
npm run build
npm run tauri -- build --debug
```

Estado:

- Frontend: OK
- Backend/Tauri: OK
- Instaladores MSI y NSIS: OK

## 13. Iteracion de correcciones y nuevas funciones (Delete/VT/Threats/indicadores)

### 13.1 Alertas: Delete funcional

- `Delete` ahora marca la alerta como `deleted` en almacenamiento persistente.
- Se evita recreacion inmediata de la misma alerta usando deduplicacion contra historial reciente.

Archivos:

- `src-tauri/src/models.rs`
- `src-tauri/src/storage/mod.rs`
- `src-tauri/src/app_state.rs`

### 13.2 VT abre navegador predeterminado

- Se agrego comando nativo `open_url_in_browser` (usa `explorer.exe`).
- Los botones `VT` en procesos/programas/amenazas usan ese comando.

Archivos:

- `src-tauri/src/main.rs`
- `src/lib/api.ts`
- `src/components/ProcessTable.tsx`
- `src/components/ProcessTree.tsx`
- `src/components/InstalledProgramsTable.tsx`
- `src/components/ThreatsTable.tsx`

### 13.3 Indicador de carga de procesos

- Se agrego banner de carga en la pestana `Processes` mientras se refresca snapshot de procesos.

Archivo:

- `src/App.tsx`

### 13.4 Personalizacion de color/etiqueta por proceso

- Desde el circulo del indicador se puede abrir menu de personalizacion.
- Permite definir color (`green/yellow/red`) y etiqueta libre para cualquier proceso.
- Persistencia en `known_entities.json`.

Equivalencia de color:

- `green` -> `windows_native`
- `yellow` -> `trusted`
- `red` -> `unknown`

Archivos:

- `src/components/TrustIndicator.tsx`
- `src/App.tsx`
- `src/lib/api.ts`
- `src-tauri/src/main.rs`
- `src-tauri/src/app_state.rs`
- `src-tauri/src/storage/mod.rs`
- `src-tauri/src/models.rs`

### 13.5 Nueva pestana Threats

- Nueva vista `Threats` con procesos potencialmente peligrosos (`risk != legitimate`).
- Incluye CPU/GPU/memoria, score y evidencias.

Archivo:

- `src/components/ThreatsTable.tsx`
- `src/App.tsx`

### 13.6 Grafica Overview renovada

- Sustitucion por grafica de barras horizontales con lista vertical de procesos y %CPU.

Archivo:

- `src/components/UsageChart.tsx`

### 13.7 Validacion final

Comandos:

```powershell
npm run build
npm run tauri -- build --debug
```

Resultado:

- Frontend compila: OK
- Backend Tauri compila: OK
- Bundles MSI/NSIS generados: OK

## 14. Rework de estabilidad, rendimiento y arquitectura (iteracion actual)

### 14.1 Entorno de ejecucion Tauri estabilizado

- Se verifico que `cargo` ya existe en `C:\Users\asier\.cargo\bin\cargo.exe`.
- El problema de `cargo metadata` era de `PATH`, no de instalacion.
- Se valido arranque correcto con:

```powershell
npm run tauri dev
```

Script clave:

- `scripts/tauri-wrapper.ps1` (inyecta `cargo`, MSVC y SDK en entorno del proceso).

### 14.2 Alertas: borrado real y borrado masivo

- `delete_alert` ahora elimina fisicamente la alerta del store.
- Nuevo comando `delete_all_alerts` para eliminar todas las alertas activas.
- UI actualizada con boton `Delete all` en panel de alertas.

Archivos:

- `src-tauri/src/storage/mod.rs`
- `src-tauri/src/app_state.rs`
- `src-tauri/src/main.rs`
- `src/lib/api.ts`
- `src/components/AlertsPanel.tsx`
- `src/App.tsx`

### 14.3 Confianza/etiquetas: persistencia consistente (sin revertir)

- Se sincronizan aliases de proceso por nombre/ruta para evitar colisiones historicas.
- Al resolver override, prevalece la entidad mas reciente por timestamp.
- Se actualiza snapshot en caliente tras guardar confianza/etiqueta.

Archivos:

- `src-tauri/src/storage/mod.rs`
- `src-tauri/src/app_state.rs`

### 14.4 Acciones externas y Explorer robustos

- Apertura de URLs movida a `cmd /C start` con fallback en frontend (`window.open`).
- Ajuste de apertura de Explorer por archivo con `"/select,<path>"` en un solo argumento.

Archivos:

- `src-tauri/src/main.rs`
- `src/App.tsx`

### 14.5 Optimizacion de monitorizacion backend

- Colector de procesos convertido a instancia persistente (`OnceLock + Mutex`) para evitar recrear `System` cada ciclo.
- Se limito el presupuesto de comprobaciones de firma por tick para reducir carga de PowerShell.

Archivos:

- `src-tauri/src/monitoring/process_collector.rs`
- `src-tauri/src/monitoring/mod.rs`

### 14.6 Rework arquitectonico frontend

- Se extrajo la logica de polling/carga/mutaciones de datos a un hook dedicado:
  - `src/hooks/useMonitoringData.ts`
- `App.tsx` queda centrado en orquestacion UI y dialogo de proceso.
- Se aplico code-splitting por pestanas (`React.lazy` + `Suspense`) para reducir carga inicial.

Archivos:

- `src/hooks/useMonitoringData.ts`
- `src/App.tsx`

### 14.7 Rework visual Obsidian Pro

- Rediseno completo del tema dark/light con superficies y contraste mas profesional.
- Esquinas casi rectas en cards/paneles/dialogos.
- Mejoras de legibilidad y consistencia responsive.

Archivo:

- `src/styles/global.css`

### 14.8 Validacion de esta iteracion

Comando ejecutado:

```powershell
npm run build
```

Resultado:

- TypeScript: OK
- Vite build: OK
- Bundle ahora dividido por modulos/pestanas (mejor carga inicial)
