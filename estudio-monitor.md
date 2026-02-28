# Estudio tecnico para fortalecer monitoreo de seguridad en tiempo real (Windows)

## 1) Objetivo
Definir un marco tecnico para que tu programa no solo "observe procesos", sino que clasifique actividad en:

- `Benigno`
- `Sospechoso`
- `Malicioso probable`
- `Malicioso confirmado`

El enfoque cubre:

- procesos y aplicaciones
- suplantacion de procesos legitimos
- inyeccion de codigo y manipulacion en memoria
- trackers y exfiltracion
- red (puertos, conexiones entrantes/salientes, anomalias)
- cambios de registro criticos
- defensas y respuesta automatizada

## 2) Arquitectura recomendada (pipeline)
Implementa una arquitectura por capas para evitar un monitor "superficial":

1. `Collectors` (captura): proceso, red, registro, eventos de seguridad, firmas, hashes.
2. `Normalizer` (normalizacion): convierte eventos a un esquema unico.
3. `Enrichment` (enriquecimiento): firma digital, reputacion hash/IP/dominio, geolocalizacion ASN, parent chain, baseline.
4. `Detection Engine` (deteccion): reglas + heuristicas + scoring.
5. `Response Engine` (respuesta): alertar, aislar, bloquear, cuarentena, rollback.
6. `Storage` (retencion): eventos crudos + timeline + evidencia.
7. `UI/API` (operacion): triage rapido y explicable.

## 3) Fuentes de telemetria minimas en Windows
Para deteccion real necesitas varias fuentes, no solo lista de procesos:

- Enumeracion de procesos/hilos/modulos (`Toolhelp32`, `NtQuerySystemInformation`).
- Metadata del ejecutable: ruta, hash (`SHA-256`), version, company name, signer.
- Validacion Authenticode/certificado (cadena, fecha, revocacion si es posible).
- Conexion de red por proceso (`GetExtendedTcpTable`/`GetExtendedUdpTable`).
- Eventos ETW/Sysmon/Windows Event Log (si puedes integrarlo).
- Registro (claves de persistencia, seguridad, politicas).
- Tareas programadas, servicios, WMI subscriptions, extensiones de navegador.

## 4) Modelo de datos por proceso (imprescindible)
No te quedes en `PID + nombre`. Captura por cada proceso:

- `pid`, `ppid`, `image_name`, `image_path`, `cmdline`, `cwd`
- `user_sid`, `username`, `integrity_level`, `elevated`
- `start_time`, `uptime`, `session_id`
- `sha256`, `imphash` (opcional), tamano binario
- `signer_status` (signed/unsigned/invalid/mismatch)
- `parent_chain` completa (abuelo/bisabuelo)
- numero de hilos, handles, modulos cargados
- conexiones activas/listening y puertos
- rutas de DLL cargadas fuera de ubicaciones confiables
- indicadores de memoria ejecutable privada (si puedes inspeccionar)

## 5) Deteccion de suplantacion de procesos legitimos
Casos comunes: proceso con nombre legitimo pero binario malicioso.

### Senales fuertes
- Nombre legitimo en ruta no legitima.
  - Ejemplo: `svchost.exe` fuera de `C:\Windows\System32\`.
- Proceso de sistema sin firma valida Microsoft.
- Parent-child imposible.
  - Ejemplo: `winlogon.exe` iniciado por proceso de usuario.
- Typosquatting/homoglifos.
  - Ejemplo: `expl0rer.exe`, `scvhost.exe`.
- Command line anomala para binario legitimo.
- Binario firmado pero certificado revocado/no esperado para ese proceso.

### Controles practicos
- Catalogo de procesos core con reglas de ruta+firmante+parent esperado.
- Distancia de Levenshtein para detectar nombres parecidos.
- Lista de ubicaciones de alto riesgo (`%TEMP%`, `%APPDATA%`, `Downloads`) ejecutando nombres de sistema.

## 6) Deteccion de inyeccion y manipulacion de memoria
Objetivo: detectar apps legitimas comprometidas.

### Indicadores de inyeccion
- Un proceso obtiene handle con permisos de escritura/ejecucion sobre otro (`PROCESS_VM_WRITE`, `PROCESS_CREATE_THREAD`).
- Secuencia tipica: `OpenProcess -> VirtualAllocEx -> WriteProcessMemory -> CreateRemoteThread`.
- Hilos cuyo start address cae fuera de modulos mapeados legitimos.
- Paginas `RWX` o `RX` privadas sin archivo de respaldo.
- Modulos reflectivos/manual map (DLL sin entrada normal en loader).
- `QueueUserAPC` o `SetThreadContext` en contexto anomalo.

### Estrategia de deteccion
- Reglas de secuencia temporal (correlacion de 2-5 eventos).
- Baseline por aplicacion (por ejemplo, navegador hace inyecciones legitimas en sandbox, notepad no).
- Score mas alto si objetivo es proceso sensible (`lsass.exe`, navegador, cliente bancario, EDR).

## 7) Deteccion de aplicaciones maliciosas o comprometidas

### Validaciones de integridad
- Comparar hash del ejecutable contra baseline conocido.
- Alertar si un binario instalado cambia sin update esperado.
- Monitorear reemplazo de DLL en carpetas de app (DLL hijacking).

### Senales de comportamiento
- Office/PDF reader lanzando `cmd`, `powershell`, `wscript`, `mshta`.
- Browser lanzando procesos de scripting fuera de patron habitual.
- Proceso recien creado que establece persistencia inmediatamente.
- "Burst" de conexiones a muchos dominios/IP en corto tiempo.

## 8) Trackers y exfiltracion
Separar privacidad de malware, pero detectarlo igual.

### Trackers potenciales
- Conexiones recurrentes a dominios de ad/analytics/tracking.
- Telemetria excesiva con IDs persistentes (machine ID, user fingerprint).
- DNS queries con alta cardinalidad de subdominios (posible tracking/beacon).

### Exfiltracion sospechosa
- Uploads constantes con bajo throughput periodico (beacon C2).
- Envio a infraestructura recien registrada o ASN de hosting "bulletproof".
- Uso inesperado de `DoH/DoT`, tunneling DNS o HTTP over non-standard ports.

### Controles
- Clasificacion de dominios: business-critical vs tracker vs unknown.
- Umbrales por proceso (bytes out/min, destinos nuevos/dia).
- Alertas por primer contacto a dominio nunca visto.

## 9) Analisis de red: puertos y conexiones extranas

### Puertos abiertos (listening)
Clasifica cada puerto por:

- proceso propietario
- interfaz (`127.0.0.1` vs `0.0.0.0` vs IP publica)
- protocolo (`TCP/UDP`)
- necesidad de negocio

### Riesgo alto tipico
- Servicios administrativos expuestos en interfaces publicas.
- Puertos legacy inseguros o inesperados para endpoint de usuario.
- Servicio desconocido escuchando con privilegios altos.

### Conexiones entrantes sospechosas
- Reintentos repetidos desde muchas IP (escaneo).
- Intentos en abanico de puertos en ventanas cortas.
- Handshakes incompletos altos (SYN scan behavior).

### Conexiones salientes sospechosas
- Periodicidad exacta (beacon cada N segundos).
- Conexion a IP directa sin DNS en procesos no esperados.
- Multiples destinos geograficos inusuales en poco tiempo.
- TLS con certificado raro, autofirmado o con CN/SAN inconsistente.

## 10) Registro de Windows: cambios criticos a vigilar
Vigilar solo claves de alto impacto para no saturar.

### Persistencia
- `HKCU\Software\Microsoft\Windows\CurrentVersion\Run`
- `HKLM\Software\Microsoft\Windows\CurrentVersion\Run`
- `RunOnce`, `Winlogon\Shell`, `Userinit`
- IFEO (`Image File Execution Options`)
- `AppInit_DLLs`, `KnownDLLs` (alta criticidad)

### Desactivacion de defensas
- Claves relacionadas con Defender, Firewall, UAC, SmartScreen.
- Politicas de deshabilitacion de actualizaciones de seguridad.

### Ejecucion lateral / script abuse
- Asociaciones de archivo/script alteradas para ejecutar payloads.
- Cambios en PowerShell policy o logging.

### Reglas de deteccion en registro
- `Who + What + OldValue + NewValue + Process + Signature`.
- Alertar alto si modifica seguridad y el proceso es unsigned/desconocido.

## 11) Baseline inteligente (clave para bajar falsos positivos)
Sin baseline, todo parece sospechoso.

### Baseline inicial
- 7-14 dias de aprendizaje por host/perfil.
- Construir perfiles de normalidad por franja horaria.
- Guardar: procesos habituales, parent chains, puertos, dominios frecuentes.

### Baseline continuo
- Actualizar de forma controlada (no auto-aceptar todo).
- Requerir confianza para promover nuevos comportamientos a "normal".
- Versionar baseline para poder rollback tras incidente.

## 12) Motor de scoring y veredicto
Cada senal aporta puntuacion y confianza.

### Ejemplo de categorias
- `0-24`: Benigno
- `25-49`: Bajo riesgo
- `50-74`: Sospechoso
- `75-100`: Malicioso probable

### Factores para el score
- Criticidad de la senal (inyeccion > puerto nuevo).
- Calidad de evidencia (hash reputado vs heuristica debil).
- Contexto (proceso firmado, usuario admin, hora inusual).
- Correlacion multi-dominio (proceso + red + registro en 5 min).

## 13) Respuesta y defensas automatizadas
Respuesta progresiva para no romper el sistema.

### Niveles de accion
1. `Audit`: solo log + alerta.
2. `Contain`: bloquear red del proceso, suspender proceso.
3. `Remediate`: matar proceso, eliminar persistencia, cuarentena binario.
4. `Recover`: restaurar claves criticas y reglas seguras.

### Recomendaciones
- Anadir "safe mode": no terminar procesos criticos sin confirmacion.
- Mantener lista protegida de procesos del sistema.
- Registrar toda accion con motivo y evidencia (audit trail).

## 14) Trazabilidad y evidencia forense
Cada alerta debe ser explicable y reproducible.

Guardar:

- evento original
- evidencia enriquecida (hash, firma, geoip, parent chain)
- regla/heuristica que disparo
- score final y factores contribuyentes
- acciones tomadas y resultado

Formato recomendado: JSON estructurado + timeline indexada por `host, pid, timestamp`.

## 15) Rendimiento y estabilidad en tiempo real
Evita que la seguridad degrade el endpoint.

- Usar colas y procesamiento asincrono.
- Muestreo para inspecciones pesadas de memoria.
- Cache de firmas/hashes para no recalcular continuamente.
- Limites de CPU/memoria por modulo.
- "Backpressure" si la tasa de eventos se dispara.

## 16) Endurecimiento del propio monitor
Tu software tambien puede ser objetivo.

- Autoproteccion basica (integridad de binarios/config).
- Watchdog del servicio principal.
- Firma de tus componentes y verificacion en arranque.
- Canal seguro para updates (firmados, con rollback).
- Proteccion de logs contra borrado/manipulacion.

## 17) Plan de implementacion por fases

### Fase 1 (MVP util)
- Inventario de procesos enriquecido (ruta, hash, firma, parent).
- Mapa de conexiones por proceso.
- Monitor de claves Run/RunOnce/Winlogon.
- Motor de reglas simple + score.

### Fase 2 (deteccion avanzada)
- Correlacion temporal multi-fuente.
- Deteccion de suplantacion robusta.
- Deteccion de secuencias de inyeccion.
- Baseline con aprendizaje controlado.

### Fase 3 (respuesta y resiliencia)
- Contencion automatica por niveles.
- Cuarentena y rollback de persistencia.
- Trazabilidad forense completa.

### Fase 4 (madurez)
- Integracion con fuentes de reputacion.
- Afinado de precision (FP/FN).
- Panel de riesgo por host y tendencia.

## 18) Pruebas que debes incluir

### Pruebas funcionales
- Crear proceso benigno esperado -> no alerta alta.
- Simular `svchost.exe` en carpeta temporal -> alerta alta.
- Modificar `Run` con ejecutable unsigned -> alerta alta.
- Abrir puerto listening inesperado -> alerta media/alta.

### Pruebas de regresion
- Actualizacion legitima de app firmada -> no falso positivo critico.
- Navegador con trafico normal de CDNs -> no clasificar como C2.

### Pruebas de rendimiento
- Carga sostenida de miles de eventos/minuto.
- Latencia de deteccion objetivo < 1-3 segundos en reglas criticas.

## 19) Riesgos comunes de diseno (y como evitarlos)

- Exceso de reglas estaticas -> romper con cambios legitimos.
  - Mitigar con baseline + reputacion + contexto.
- Demasiados falsos positivos -> usuario ignora alertas.
  - Mitigar con scoring y severidad explicable.
- Respuesta agresiva -> caidas del sistema.
  - Mitigar con contencion gradual y listas protegidas.
- Falta de evidencia -> no se puede investigar.
  - Mitigar con logging estructurado y retencion minima.

## 20) Checklist minimo de produccion

- [ ] Proceso: ruta+hash+firma+parent chain
- [ ] Red: puertos listening + conexiones por proceso
- [ ] Registro: Run/RunOnce/Winlogon/IFEO + seguridad
- [ ] Heuristicas de suplantacion
- [ ] Heuristicas de inyeccion (al menos secuencias basicas)
- [ ] Baseline inicial + aprendizaje controlado
- [ ] Score explicable por alerta
- [ ] Acciones de respuesta por niveles
- [ ] Logs forenses estructurados
- [ ] Pruebas de precision y rendimiento

## 21) Criterio practico de exito
Tu sistema esta en buen nivel cuando:

- detecta rapidamente procesos suplantados y persistencia anomala
- identifica actividad de red sospechosa por proceso, no solo por host
- correlaciona proceso+red+registro en una sola historia
- mantiene tasa de falsos positivos manejable
- puede contener incidentes sin romper operaciones normales
