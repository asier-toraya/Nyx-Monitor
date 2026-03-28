# Write-up Nyx Monitor

## Contexto

Este proyecto empezó como una idea sencilla: "quiero ver qué está pasando en mi PC en tiempo real". Al principio se llamaba P-Control, y con el tiempo lo fui puliendo hasta convertirlo en Nyx Monitor, con una interfaz más cuidada y un enfoque más serio en monitorización y análisis de confianza.

No fue un desarrollo lineal perfecto. Fue bastante iterativo: iba implementando, probando en local, encontrando fallos reales y corrigiendo sobre la marcha.

## Qué quería conseguir

Los objetivos principales fueron:

- Ver procesos en ejecución y su estructura padre/hijo.
- Ver consumo de CPU y GPU por proceso.
- Distinguir procesos confiables de procesos desconocidos.
- Detectar actividad sospechosa sin llenar la app de falsos positivos.
- Mostrar software instalado, procesos de inicio y algo de historial de uso.
- Tener una interfaz agradable y útil para uso diario.

## Stack que elegí

Al final, la combinación fue:

- Frontend: React + TypeScript + Vite.
- Escritorio: Tauri 2.
- Backend: Rust.
- Gráficas: Recharts.
- Persistencia local:
  - JSON para alertas, entidades conocidas y acciones.
  - SQLite para timeline de eventos.

La razón principal de elegir Tauri + Rust fue rendimiento y acceso nativo en Windows, sin irme a Electron.

## Cómo funciona por dentro (resumen)

Nyx Monitor corre un loop en background que va recogiendo telemetría de procesos. Con esos datos:

1. Construye snapshot de procesos y árbol de procesos.
2. Calcula confianza y evaluación heurística.
3. Aplica correlación (proceso/red/registro).
4. Genera score + veredicto.
5. Emite eventos y alertas.
6. Guarda estado en almacenamiento local.

En frontend tengo pestañas separadas para Overview, Processes, Threats, Timeline, Health, Response, Alerts, Installed, Startup y History.

## Funcionalidades que implementé

### Monitorización y análisis

- Process Tree con expandir/contraer y búsqueda.
- Running Processes con CPU/GPU/memoria, PID/PPID, ruta, score y veredicto.
- Popup de proceso con:
  - Datos técnicos.
  - Hash SHA-256.
  - Búsqueda en VirusTotal (hash o nombre).
  - Búsqueda en Google.
  - Cambio manual de confianza y etiqueta.
- Pestaña Threats para revisar procesos con riesgo.

### Inventario y contexto del sistema

- Installed programs clasificados por confianza.
- Startup processes (arranque de sistema).
- App usage history.
- Event timeline con eventos de proceso, red, registro y respuesta.
- Health panel para estado de sensores/rendimiento interno.

### Alertas y respuesta

- Alertas activas y borrado individual/masivo.
- Deduplificación y supresión temporal de alertas borradas.
- Política de respuesta (audit/constrain) y acciones manuales.

### UX y producto

- Modo claro/oscuro.
- Instalador para usuario final vía GitHub Releases.
- Workflow de release automático con tags (`v*`).

## Problemas reales que me encontré

Estos fueron de los más importantes:

1. Entorno Windows para compilar Tauri
- `cargo metadata` fallaba porque no estaba Rust en PATH.
- Luego aparecieron problemas de `link.exe` y `kernel32.lib`.
- Solución: instalar toolchain correcta (Rust + Build Tools + SDK) y usar wrapper de PowerShell.

2. Falsos positivos demasiado agresivos
- Al principio se marcaban cosas legítimas (ChatGPT.exe, incluso el propio monitor).
- Causa: scoring y correlación con pesos altos y reglas poco contextuales.
- Solución: endurecer veredicto final, bajar peso de correlación, mejorar trust baseline y tratar procesos internos como confiables.

3. Alertas que "volvían" después de borrar
- Se borraban visualmente, pero reaparecían por la misma señal en poco tiempo.
- Solución: supresión temporal por firma de alerta + dedupe más estricto.

4. Overrides de confianza que no persistían bien
- Cambiar color/label a veces se revertía al refrescar.
- Solución: mejorar sincronización de aliases y refresco del snapshot tras guardar.

5. UX con comportamientos molestos
- Badges/parpadeos, botones VT no siempre abriendo navegador y ventanas abriendo doble.
- Solución: varios ajustes en eventos, handlers y comandos Tauri.

6. CI/release
- El primer workflow de release dio problemas.
- Solución: simplificar y usar flujo de release por tags para generar instalador NSIS en GitHub Actions.

## Cosas que aprendí

- En apps de seguridad, "menos ruido" es casi tan importante como "detectar cosas".
- No basta con sacar features: hay que pulir comportamiento en uso real (alertas, refresco, UX).
- Tener comandos y contratos frontend/backend bien definidos reduce muchos bugs raros.
- Documentar y automatizar release evita dolor cada vez que quiero sacar versión.

## Estado actual

Ahora Nyx Monitor ya está en un punto útil:

- Monitoriza procesos y contexto del sistema en tiempo real.
- Permite análisis técnico desde UI (hash, VT, confianza, proceso padre).
- Tiene pipeline de release para que un usuario normal pueda descargar e instalar con un `.exe`.

Todavía no pretende ser un EDR enterprise, pero como herramienta personal de observabilidad y triage va bastante bien.
