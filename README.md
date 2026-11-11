# F5AuditDNS — Auditoría de F5 BIG-IP DNS / GSLB

**Versión:** 0.1.2 (prototipo funcional, pendiente de validación contra un BIG-IP DNS real; diseñado inicialmente para la estructura REST de TMOS 12+)  
**Plataformas:** Windows / Linux / macOS, Python 3.9+  
**Proyecto independiente:** no modifica, instala ni importa `f5audit` (LTM).

F5AuditDNS reutiliza la filosofía de F5Audit LTM: **READ ONLY → RAW JSON → CORRELACIÓN → REPORTE**.

> **Advertencia de producción:** esta versión valida la estructura de configuración GSLB, no acredita que un recurso esté inactivo por falta de tráfico. Ningún hallazgo autoriza una eliminación. No genera comandos `delete` ni `modify`.

## 1. ¿Qué audita?

```text
  Wide IP (app.empresa.example)
       |
       +-- GSLB Pool A: pool_app
       |       +-- GSLB member GDL-F5:vs_app
       |       +-- GSLB member QRO-F5:vs_app
       |
       +-- Last Resort Pool: pool_fallback (A o CNAME)

  Data Center (DC_GDL)
       +-- GSLB Server (GDL-F5)
               +-- GSLB Virtual Server (vs_app)
```

| Objeto | Estado v0.1.0 | Evaluación |
|---|---|---|
| Wide IP A / AAAA / CNAME / MX / NAPTR / SRV | Incluido | Pools asociados, reglas, Last Resort Pool, enabled/disabled |
| GSLB Pool por tipo de registro | Incluido | Miembros, referencias directas de Wide IP, método y monitor |
| GSLB Pool Member | Incluido | Resolución *conservadora* a Server + Virtual Server |
| GSLB Server | Incluido | Data Center, virtual servers y referencias mapeadas |
| GSLB Virtual Server | Incluido | IP/puerto cuando API lo proporciona, estado configuración |
| Data Center | Incluido | Servidores asociados |
| Monitores GTM, Listeners, iRules, Topology, Regions, Prober Pools | Inventario opcional | Sin decidir si están en desuso |
| DNS Express, DNS Cache, Zones, DNSSEC, DNS Sync Groups | **No incluidos** | Propuesta de versiones futuras |
| Estadísticas históricas, Queries/sec, disponibilidad temporal | **No incluidos** | No puede afirmarse inactividad por cero tráfico |

### Diferencia importante entre configuración y salud

- **Config: ENABLED / DISABLED / UNKNOWN** describe si el objeto está administrativamente habilitado.
- **Health: UP / DOWN / UNKNOWN** se llena solamente cuando el JSON expone un campo de disponibilidad compatible. En muchos snapshots de *configuración* será `UNKNOWN`.
- La ausencia de información equivale a `UNKNOWN`, **nunca a `EMPTY`, `DOWN` o `ORPHAN`**.

## 2. Instalación en Windows (PowerShell)

Descomprime el ZIP del proyecto. Abre PowerShell en la carpeta que tiene `pyproject.toml`.

```powershell
cd D:\Automation_Projects\F5AuditDNS
py -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
python -m pip install -e ".[dev]"

f5auditdns --version
f5auditdns --help
```

Si PowerShell bloquea la activación, puedes usar directamente:

```powershell
.\.venv\Scripts\python.exe -m pip install -e ".[dev]"
.\.venv\Scripts\python.exe -m f5auditdns --help
```

### Dependencias

- `requests`: iControl REST por HTTPS.
- `openpyxl`: formato Excel.
- `pytest` (opcional): tests de desarrollo.

**No necesita:** Linux, pyATS, Genie, Netmiko ni acceso SSH para la auditoría inicial. También puedes instalar dependencias con `py -m pip install -r requirements.txt`.

## 3. Uso paso a paso

### 3.1 Validar lectura en la API (IP o nombre DNS)

```powershell
# IP de administración
f5auditdns validate -ho 192.0.2.20 -u auditor
f5auditdns validate -ho 192.0.2.20 -u auditor --insecure

# Nombre de dominio (FQDN) de administración
f5auditdns validate -ho f5auditdns.com -u auditor
f5auditdns validate -ho f5auditdns.com -u auditor --insecure
```

`-ho` puede ser una IP o un nombre que resuelva por DNS hacia la **interfaz de administración HTTPS** del F5; `f5auditdns.com` es un ejemplo de formato, no un endpoint de laboratorio disponible.

La contraseña se solicita sin mostrarla. Por defecto se verifica el certificado HTTPS. `--insecure` deshabilita esta verificación y debe reservarse para laboratorios o casos controlados.

### 3.2 Recopilar información (carpeta automática)

**Recomendado: sin `-o`**, la herramienta consulta por lectura `/mgmt/tm/sys/global-settings` para descubrir el hostname del BIG-IP y crea una carpeta nueva en el **directorio desde el que ejecutas `collect`**. Utiliza la fecha y hora local de inicio de ejecución:

```text
f5auditDNS_raw_<hostname>_<YYYYMMDD_HHMM>/
```

Si la API no devuelve hostname o responde con error, utiliza el valor suministrado con `-ho` y muestra un aviso. Para evitar sobrescrituras, si ejecutas dos recopilaciones del mismo F5 en un minuto, la segunda carpeta agrega `_02`, `_03`, etc.

```powershell
# Con una IP de administración
f5auditdns collect -ho 192.0.2.20 -u auditor --insecure

# Con un FQDN de administración
f5auditdns collect -ho f5auditdns.com -u auditor
f5auditdns collect -ho f5auditdns.com -u auditor --insecure
```

Salida ilustrativa (un F5 que reporta `dns01.empresa.example`):

```text
Collecting BIG-IP DNS/GSLB: 192.0.2.20 | scope=all
BIG-IP password: ********
Raw snapshot saved: .\f5auditDNS_raw_dns01.empresa.example_20261111_1653 | OK datasets: 35 | warnings: 0
The audit is read-only; no configuration was modified.

Next step: analyze this snapshot (run in the SAME directory):
  f5auditdns analyze --from-raw ".\f5auditDNS_raw_dns01.empresa.example_20261111_1653" -o ".\DNS_Audit.xlsx"
```

El archivo `DNS_Audit.xlsx` se genera en el **directorio actual**, junto a la carpeta de snapshot, no dentro de ella.

### 3.3 Recopilar información (carpeta manual)

Puedes seguir usando `-o` para fijar una carpeta personalizada:

```powershell
f5auditdns collect -ho 192.0.2.20 -u auditor --insecure -o .\raw_dns
f5auditdns collect -ho f5auditdns.com -u auditor --insecure -o .\raw_dns
f5auditdns collect -ho 192.0.2.20 -u auditor -o .\raw_dns_core --scope core --verbose
```

Al terminar, **siempre imprime el comando `analyze`** con la ruta real de la carpeta elegida, ya sea manual o automática, incluso cuando existan advertencias y se guarde un snapshot incompleto.

- `--scope core`: Wide IPs, GSLB Pools, Members, Servers, Virtual Servers, Data Centers.
- `--scope all` (predeterminado): también consulta Monitors, iRules, Listeners, Topology, Regions y Prober Pools.
- Las carpetas existentes con datos no se sobrescriben.
- Si algún endpoint devuelve `403`, `404` u otro error, queda registrado en `Collection Health`.
- Los JSON contienen información de infraestructura y deben protegerse.

### 3.4 Analizar offline, generar Excel o CSV

```powershell
f5auditdns analyze --from-raw .\raw_dns -o .\DNS_Audit.xlsx
f5auditdns analyze --from-raw .\raw_dns --format csv -o .\reports_csv
```

Este análisis no requiere conectividad con el BIG-IP ni `--insecure`.

### 3.5 Ayuda y más ejemplos

```powershell
f5auditdns --help
f5auditdns validate --help
f5auditdns collect --help
f5auditdns analyze --help
```

Tanto la ayuda principal como la de `validate` y `collect` incluyen ejemplos con IP, FQDN y `--insecure`.

### 3.6 Ejemplo offline sin F5

El ZIP incluye una captura **completamente ficticia** para practicar:

```powershell
f5auditdns analyze --from-raw .\examples\raw_simulado -o .\DNS_Audit.xlsx
```

Para regenerar el snapshot ficticio, vacía antes la carpeta y ejecuta:

```powershell
python .\examples\generate_sample.py
```

## 4. Hojas de reporte (11)

| Hoja Excel | Pregunta que responde |
|---|---|
| Summary | ¿Cuántos objetos tiene este snapshot? ¿Está completo? |
| Wide IP Findings | ¿Qué dominios tienen Pools, reglas y Last Resort? |
| GSLB Pool Findings | ¿Qué Pools tienen miembros? ¿Qué Wide IPs los referencian? |
| Pool Members | ¿Qué miembro pertenece a qué Pool? ¿Pude resolverlo al GSLB Server? |
| GSLB Servers | ¿Qué servidores existen y a qué Data Center pertenecen? |
| GSLB Virtual Servers | ¿Qué servicios tiene cada Server? |
| Data Centers | ¿Cuántos GSLB Servers están asociados? |
| DNS Chains | ¿Cuál es la cadena Wide IP → Pool → Member → Server → VS? |
| Manual Review | ¿Qué referencias o configuraciones necesitan revisión? |
| Auxiliary Inventory | ¿Qué Monitors, iRules, Listeners, etc. fueron recopilados? |
| Collection Health | ¿Qué consultas API fueron completadas, rechazadas o faltan? |

### Interpretación de una cadena

```text
A /Common/app.empresa.example
  -> A /Common/pool_app
     -> /Common/GDL-F5:/Common/vs_app
        -> GDL-F5
           -> 192.0.2.100:443
```

Este vínculo **no prueba** que el destino esté activo o reciba consultas. Solo muestra asociaciones reconocidas por la herramienta.

### Ejemplos de hallazgos

| Hallazgo | Significado |
|---|---|
| `REFERENCED` | Existe una referencia directa mapeada, no una garantía de uso |
| `MANUAL REVIEW: no direct Wide IP reference` | No está en una lista directa; podría ser usado por iRules, fallback u otros mecanismos |
| `MANUAL REVIEW: no members` | El Pool aparece vacío; revisar diseño, fallback y mantenimiento |
| `DATA GAP` | Endpoint/subcolección no accesible o referencia no resoluble |
| `DISABLED` | Estado administrativo, no autorización para borrar |
| `UNKNOWN` | La API no proporcionó evidencia suficiente |

## 5. Seguridad

- Todas las consultas de inventario son **GET**.
- **Único POST:** `/mgmt/shared/authn/login` para solicitar el token de autenticación.
- No existen comandos CLI para modificar, eliminar o restaurar configuración.
- Contraseña oculta con `getpass`; se admite `F5AUDITDNS_PASSWORD` para automatización segura.
- Certificado TLS verificado por defecto. `--insecure` es opcional y se recomienda solo para laboratorio.
- Los snapshots tienen identificadores únicos; una carpeta con datasets mezclados se rechaza.
- Nombres o descripciones de F5 se protegen contra inyección de fórmulas de Excel.
- Se recomienda una cuenta de **solo lectura** y proteger el directorio de snapshots/reports.

## 6. Estructura del proyecto

```text
F5AuditDNS/
├── f5auditdns/
│   ├── __init__.py             # Version
│   ├── __main__.py             # python -m f5auditdns
│   ├── client.py               # Reutilizado/adaptado de F5Audit LTM
│   ├── cli.py                  # validate / collect / analyze
│   ├── collector.py            # REST + JSON snapshots
│   ├── analyzer.py             # Correlaciones GSLB
│   └── report.py               # Excel + CSV
├── tests/                      # Pruebas offline
├── examples/raw_simulado/      # Datos ficticios
├── README.md                   # Esta guía
├── PROJECT_CONTEXT.md         # Estado/alcance/versionado
├── CHANGELOG.md               # Historial de versiones
├── requirements.txt           # Dependencias principales
├── NOTICE.md                   # Atribución MIT F5Audit
├── LICENSE
└── pyproject.toml
```

## 7. Limitaciones conocidas de v0.1.0

1. **No validada contra dispositivos reales.** Se deben confirmar propiedades, referencias y permisos con la versión TMOS de tu ambiente.
2. Las rutas REST de las subcolecciones y los datos devueltos pueden diferir entre versiones. Si no hay pruebas concluyentes, se marca `UNKNOWN`.
3. Los campos `enabled`/`disabled` no sustituyen las estadísticas de disponibilidad operativa.
4. No es un auditor de zonas DNS ni de DNS Express, Cache o DNSSEC; se centra en GSLB.
5. No hay análisis temporal ni comparación de snapshots.
6. No hay soporte de múltiples hosts en una sola ejecución.
7. No hay comandos `tmsh` de eliminación ni rollback intencionalmente. Estos deben planificarse solo después de validar dependencias y comportamiento del equipo.

## 8. Próximos pasos

**v0.2.0:** validar snapshots de TMOS reales; mejorar correlación en particiones/subPaths y estados health; capturar estadísticas reales y diagnósticos de monitor.  
**v0.3.0:** comparación de snapshots y hallazgos por períodos.  
**v0.4.0:** múltiples BIG-IP DNS y reporte consolidado.  
**v0.5.0:** DNS Services (Zones, DNS Express, DNSSEC, Cache) como módulo separado.  
**Futuro:** un reporte DNS → LTM de extremo a extremo, manteniendo los repositorios independientes.

## 9. Referencias F5

- BIG-IP DNS operations guide: https://my.f5.com/manage/s/article/K55502976
- GTM REST resources: https://clouddocs.f5.com/api/icontrol-rest/APIRef_tm_gtm.html
- GTM Wide IP A: https://clouddocs.f5.com/api/icontrol-rest/APIRef_tm_gtm_wideip_a.html
- GTM Pool A: https://clouddocs.f5.com/api/icontrol-rest/APIRef_tm_gtm_pool_a.html
- GTM Server: https://clouddocs.f5.com/api/icontrol-rest/APIRef_tm_gtm_server.html
- REST API and subcollections: https://cdn.f5.com/websites/devcentral.f5.com/downloads/icontrol-rest-api-user-guide-16-1-0.pdf

### Licencia y atribución

El cliente REST deriva del paquete F5Audit LTM 0.7.0 aportado como referencia. Se conserva la licencia MIT original y se documenta la atribución en `NOTICE.md`.
