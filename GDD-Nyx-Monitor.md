# GDD Nyx Monitor

## 1. Documento
- Proyecto: `Nyx Monitor`
- Tipo: `GDD / Documento de diseno tecnico`
- Objetivo: disenar un programa de monitoreo y defensa de endpoint Windows en tiempo real, con foco en deteccion de procesos maliciosos, inyeccion, actividad de red anomala, persistencia y cambios criticos en el sistema.
- Audiencia: arquitectura, backend, agente endpoint, SOC, QA de seguridad.
- Version: `v1.0`

## 2. Vision del producto
Nyx Monitor debe pasar de un monitor "superficial" (lista de procesos y puertos) a una plataforma de deteccion y respuesta en endpoint con evidencia trazable, correlacion multi-fuente y accion automatizada gradual.

Resultado esperado:
- distinguir `benigno`, `sospechoso`, `malicioso probable`, `malicioso confirmado`
- detectar suplantacion de procesos legitimos
- detectar inyeccion y tampering en memoria
- detectar persistencia y cambios de registro peligrosos
- analizar red por proceso y por host (entrante y saliente)
- detectar trackers y posible exfiltracion
- responder con playbooks seguros y auditables

## 3. Objetivos y no objetivos
### Objetivos
- Telemetria endpoint en tiempo real con bajo overhead.
- Correlacion proceso + red + registro + persistencia + reputacion.
- Alertas explicables con score y evidencia.
- Respuesta automatizada por niveles de riesgo.
- Arquitectura modular y escalable.

### No objetivos (fase inicial)
- No reemplazar un EDR comercial completo desde el dia 1.
- No hacer analisis forense de disco full-image.
- No depender de IA generativa para decisiones de bloqueo.

## 4. Requisitos funcionales
1. Inventariar procesos con metadata extendida.
2. Validar identidad binaria (ruta, hash, firma, parent chain).
3. Detectar secuencias de inyeccion interproceso.
4. Monitorear puertos listening y conexiones activas por proceso.
5. Monitorear cambios de claves de registro criticas.
6. Detectar persistencia no registro (scheduled tasks, servicios, WMI, startup).
7. Detectar abuso de LOLBins.
8. Detectar patrones de robo de credenciales.
9. Detectar evasion/antiforense basica.
10. Correlacionar eventos y calcular score de riesgo.
11. Ejecutar respuesta automatizada por politica.
12. Registrar evidencia completa para investigacion.

## 5. Requisitos no funcionales
- Latencia deteccion reglas criticas: `< 3s`.
- Overhead CPU agente promedio: `< 5%`.
- Overhead RAM agente: `< 300MB`.
- Perdida de eventos: `< 0.1%` con cola local persistente.
- Alta disponibilidad backend: `99.9%`.
- Trazabilidad completa de acciones (audit trail).
- Seguridad de transporte y almacenamiento (mTLS + cifrado at-rest).

## 6. Modelo de amenazas (resumen)
### Actores
- Malware commodity.
- Operador humano post-explotacion.
- Insider con permisos locales.
- Herramientas de red team.

### Tecnicas principales a cubrir
- Suplantacion binaria.
- Process injection y code execution remota.
- Persistencia por registro, task scheduler, servicios y WMI.
- Credential dumping.
- Defensa evasiva (log tampering, disable defender/firewall).
- C2 beaconing y exfiltracion.
- Movimiento lateral.
- BYOVD (Bring Your Own Vulnerable Driver).

## 7. Arquitectura logica de alto nivel
```
[Windows Agent]
  |-- Sensor de procesos/memoria
  |-- Sensor de red
  |-- Sensor de registro y persistencia
  |-- Normalizador + cache
  |-- Regla local critica (fast path)
  |-- Cola local durable
  |-- Respuesta local (playbooks)
        |
        v mTLS
[Ingestion API / Message Bus]
        |
        v
[Detection Core]
  |-- Correlacion temporal
  |-- Motor de reglas + scoring
  |-- Enriquecimiento TI
  |-- Baseline/anomalias
        |
        v
[Data Layer]
  |-- Hot store (busqueda)
  |-- Time-series/events
  |-- Evidence store
        |
        v
[SOC Console + API]
  |-- Triage
  |-- Investigacion timeline
  |-- Politicas y respuesta
```

## 8. Componentes del agente endpoint
### 8.1 Process and Identity Sensor
Captura por proceso:
- `pid`, `ppid`, `image_name`, `image_path`, `cmdline`
- `user`, `integrity_level`, `elevation`, `session_id`
- `sha256`, `file_size`, `compile_ts` (opcional), `signer_status`
- `parent_chain` y arbol de procesos
- modulos cargados (DLL) y rutas

### 8.2 Injection and Memory Sensor
Detecta:
- patrones `OpenProcess -> VirtualAllocEx -> WriteProcessMemory -> CreateRemoteThread`
- `QueueUserAPC`, `SetThreadContext`, `NtMapViewOfSection` sospechoso
- regiones `RWX` privadas y start address fuera de modulo legitimo
- apertura de handles peligrosos sobre procesos sensibles

### 8.3 Network Sensor
Detecta:
- sockets listening por interfaz y proceso
- conexiones entrantes/salientes por proceso
- frecuencia, periodicidad, volumen, destinos nuevos
- DNS, DoH/DoT, SNI y huella TLS (si se integra captura avanzada)

### 8.4 Registry and Persistence Sensor
Vigila:
- `Run/RunOnce`, `Winlogon`, `IFEO`, `AppInit_DLLs`, politicas de seguridad
- servicios nuevos o alterados
- scheduled tasks nuevas o modificadas
- WMI permanent event subscriptions
- startup folders y accesos directos anmalos

### 8.5 LOLBins and Script Abuse Sensor
Monitorea uso de:
- `powershell`, `cmd`, `wscript`, `cscript`, `mshta`
- `rundll32`, `regsvr32`, `certutil`, `bitsadmin`, `wmic`
- reglas por parent + cmdline + contexto de usuario

### 8.6 Self-Protection
- watchdog del agente
- firma e integridad de binarios/config
- deteccion de intento de stop/desinstalacion no autorizada
- canal de actualizacion firmado con rollback

## 9. Analitica de deteccion
### 9.1 Motor de reglas
Reglas atomicas con severidad y confianza:
- identidad binaria (ruta/firma/hash/parent esperados)
- inyeccion por secuencia de API
- persistencia inmediata tras ejecucion
- beaconing periodico
- tampering de defensa

### 9.2 Correlacion temporal
Une eventos en ventanas de tiempo:
- `Proceso sospechoso` + `modificacion Run key` + `conexion C2 nueva` en `<= 5 min`
- escala riesgo si hay multiples dominios afectados

### 9.3 Baseline adaptativo controlado
- aprendizaje inicial 7-14 dias
- baseline por host, usuario y franja horaria
- promotion a baseline solo con politicas de confianza
- versionado de baseline y rollback

### 9.4 Scoring propuesto
`risk_score = sum(signal_weight * confidence * context_multiplier) - trust_offsets`

Clasificacion:
- `0-24`: Benigno
- `25-49`: Bajo riesgo
- `50-74`: Sospechoso
- `75-89`: Malicioso probable
- `90-100`: Malicioso confirmado

## 10. Cobertura avanzada que no debes omitir
1. Persistencia no registro: Scheduled Tasks, Services, WMI, COM hijacking, Startup, LNK.
2. Credential theft: acceso a `lsass`, `sam`, `security`, dump tools.
3. Evasion: timestomping, clear logs, disable telemetry, policy tampering.
4. BYOVD: carga de drivers vulnerables y actividad kernel sospechosa.
5. Supply chain: update channel comprometido, DLL sideloading firmado.
6. Lateral movement: SMB, RDP, WinRM, PsExec, WMI remota.
7. DNS/C2 moderno: DoH, dominios DGA, fast-flux, IP direct connect.
8. Trackers/privacy risk: telemetria excesiva y fingerprinting persistente.

## 11. Modelo de datos y esquema de eventos
Formato recomendado: JSON canonical + versionado por esquema.

Campos base:
- `event_id`, `host_id`, `timestamp_utc`, `event_type`, `sensor`
- `process`, `network`, `registry`, `persistence`, `security`
- `rule_hits[]`, `risk_score`, `severity`, `verdict`
- `evidence_refs[]`, `response_actions[]`

Campos forenses minimos:
- old/new values en registro
- hash de binario y ruta exacta
- parent/child chain
- remote ip/port/domain/asn
- usuario y privilegio

## 12. Respuesta automatizada y playbooks
### Niveles de accion
1. `Audit`: alerta y evidencia.
2. `Constrain`: bloquear red del proceso, suspender.
3. `Contain`: matar proceso y remover persistencia.
4. `Recover`: restaurar claves/servicios y aislar host temporalmente.

### Guardrails de seguridad
- no terminar procesos criticos del SO sin verificacion
- modo seguro para endpoints sensibles
- toda accion requiere motivo, regla, score y operador/politica

## 13. Analisis de vulnerabilidades del endpoint
Nyx debe incluir modulo de exposicion:
- inventario de software y versiones
- correlacion con CVE conocidas (SO, apps, drivers)
- riesgo de puertos expuestos y servicios inseguros
- estado de hardening (firewall, defender, UAC, patch level)

Salida:
- `vulnerability_score` por host
- backlog de remediacion priorizado por riesgo explotable

## 14. Tecnologias recomendadas y como integrarlas
### 14.1 Agente endpoint (Windows)
- Lenguaje: `Rust` (seguridad de memoria + rendimiento) o `C++` para sensores de bajo nivel.
- Captura eventos:
  - `ETW` para procesos, imagenes cargadas, red y eventos SO.
  - `Sysmon` como fuente complementaria cuando este disponible.
  - Windows APIs (`Toolhelp`, `IP Helper`, `WinVerifyTrust`, `RegNotifyChangeKeyValue`).
- Integracion:
  - crear `collector` por dominio (process/network/registry)
  - normalizar eventos a schema comun
  - enviar por gRPC/HTTPS con cola local durable

### 14.2 Transporte e ingestion
- Protocolo: `gRPC` sobre `mTLS` o `HTTPS` firmado.
- Message bus: `Kafka` o `NATS JetStream`.
- Integracion:
  - topic por tipo de evento
  - key por `host_id`
  - retries + DLQ (dead letter queue)

### 14.3 Deteccion y correlacion
- Rule engine:
  - `Sigma` como DSL de reglas (convertidas a motor propio)
  - opcion: `OPA/Rego` para politicas complejas
- Stream processing:
  - `Flink` o `Kafka Streams` para correlacion temporal
- Integracion:
  - pipeline: parse -> enrich -> correlate -> score -> action

### 14.4 Almacenamiento
- Eventos a gran escala: `ClickHouse`.
- Busqueda investigacion: `OpenSearch`.
- Metadatos de control: `PostgreSQL`.
- Evidence store: objeto (S3 compatible / MinIO).
- Integracion:
  - TTL por tipo de dato
  - indices por `host_id`, `pid`, `rule_id`, `domain`, `sha256`

### 14.5 Threat intelligence y reputacion
- Fuentes: `VirusTotal`, `AbuseIPDB`, `URLhaus`, `AlienVault OTX`.
- Integracion:
  - cache local de reputacion con TTL
  - enrichment async para no frenar deteccion en tiempo real
  - politicas de privacidad sobre indicadores enviados

### 14.6 Deteccion de memoria y malware
- `YARA` para firmas de memoria/archivo.
- `ClamAV` opcional para capa de archivo.
- Integracion:
  - escaneo bajo demanda para artifacts de alto riesgo
  - no ejecutar escaneo full constante en endpoint productivo

### 14.7 Consola, observabilidad y operacion
- Backend API: `Go` o `Rust`.
- UI SOC: `React` + timeline y grafo de procesos.
- Observabilidad: `OpenTelemetry` + `Prometheus` + `Grafana`.
- Integracion:
  - trazas por pipeline y latencia por etapa
  - dashboards de precision, throughput y errores

### 14.8 Seguridad de plataforma
- IAM/RBAC por rol (viewer, analyst, responder, admin).
- Secret management: `Vault` o cloud secret manager.
- Integracion:
  - rotacion de certificados
  - firma de paquetes y politicas
  - auditoria de cambios de reglas

## 15. Estrategia de despliegue
### Entornos
- `Dev`: reglas experimentales y datos sinteticos.
- `Staging`: replay de eventos reales anonimizados.
- `Prod`: despliegue gradual por anillos (canary).

### Release policy
- firmas de artefactos obligatorias
- rollback automatico si error de agente supera umbral
- feature flags para sensores pesados

## 16. Plan de pruebas de seguridad y calidad
1. Unit tests por parser, normalizador y regla.
2. Integration tests extremo a extremo con eventos sinteticos.
3. Simulacion adversaria con `Atomic Red Team` y mapeo `MITRE ATT&CK`.
4. Pruebas de precision:
   - precision/recall por tipo de regla
   - tasa de falsos positivos por host y por dia
5. Performance tests:
   - throughput eventos/minuto
   - latencia P50/P95/P99
6. Chaos tests:
   - caida de bus, perdida de conectividad, backlog local, recovery

## 17. KPIs operativos
- `MTTD` (mean time to detect)
- `MTTR` (mean time to respond)
- tasa de alertas accionables
- falsos positivos por regla
- porcentaje de endpoints con baseline estable
- cobertura ATT&CK por tecnica prioritaria

## 18. Roadmap de implementacion
### Fase 0 - Fundacion (2-4 semanas)
- esquema de eventos
- agente minimo process+network+registry
- ingestion segura mTLS

### Fase 1 - Deteccion core (4-8 semanas)
- identidad binaria
- reglas de suplantacion
- reglas de persistencia y LOLBins
- consola inicial y triage

### Fase 2 - Avanzado (6-10 semanas)
- deteccion de inyeccion secuencial
- correlacion temporal multi-fuente
- baseline adaptativo controlado
- threat intel enrichment

### Fase 3 - Respuesta y hardening (4-8 semanas)
- playbooks automaticos
- autoproteccion del agente
- rollback de cambios criticos

### Fase 4 - Madurez (continuo)
- tuning de reglas por telemetria real
- cobertura ATT&CK y validacion de red team
- optimizacion de costo/rendimiento

## 19. Riesgos y mitigaciones
- Riesgo: muchos falsos positivos.
  - Mitigacion: score contextual + baseline + reputacion.
- Riesgo: impacto en endpoint.
  - Mitigacion: muestreo, cache, colas, feature flags.
- Riesgo: agente comprometido.
  - Mitigacion: anti-tamper, firma, watchdog, control de integridad.
- Riesgo: bloqueo de procesos legitimos.
  - Mitigacion: respuesta gradual y allowlist protegida.

## 20. Checklist de salida a produccion
- [ ] Telemetria multi-fuente estable
- [ ] Cobertura minima de tecnicas criticas
- [ ] Score explicable y auditable
- [ ] Playbooks seguros y testeados
- [ ] SLO de latencia y overhead cumplidos
- [ ] Seguridad de plataforma y secretos validada
- [ ] Runbooks SOC y soporte operativo listos

## 21. Recomendacion de stack inicial pragmatico
Si buscas velocidad de entrega con buen equilibrio tecnico:
- Agente: `Rust` + ETW + APIs Windows nativas
- Ingestion: `gRPC + NATS JetStream`
- Deteccion: `Go` + motor de reglas propio compatible con Sigma
- Datos: `ClickHouse + OpenSearch + PostgreSQL`
- UI: `React`
- Observabilidad: `OpenTelemetry + Prometheus + Grafana`
- Threat intel: `VirusTotal + AbuseIPDB` (con cache y limites)

## 22. Orden recomendado de integracion tecnica
1. Construir schema de eventos y cola local durable en agente.
2. Integrar sensores process + network + registro con ETW/API nativa.
3. Levantar pipeline ingestion con mTLS y DLQ.
4. Implementar reglas core de suplantacion, persistencia y LOLBins.
5. Anadir correlacion temporal y scoring contextual.
6. Integrar TI externa y cache de reputacion.
7. Activar respuesta automatizada por niveles con guardrails.
8. Ejecutar bateria ATT&CK y tuning de precision.

## 23. Criterio de exito tecnico
Nyx Monitor sera exitoso cuando:
- detecte suplantacion e inyeccion con baja latencia y evidencia clara
- relacione en una sola historia proceso, red, registro y persistencia
- reduzca falsos positivos de forma sostenible
- permita respuesta automatizada segura y reversible
- sea operable a escala con telemetria confiable y observabilidad completa
