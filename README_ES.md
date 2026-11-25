# F5AuditDNS — Guía de uso (Español)

**Versión de desarrollo:** `0.5.4` | **Python:** 3.9 o superior | **Plataformas:** Windows, Linux y macOS.

[Repositorio](https://github.com/jpesqueda/F5AuditDNS) · [English user guide](USER_GUIDE_EN.md)

F5AuditDNS es un auditor de F5 BIG-IP DNS/GSLB **de solo lectura**. Utiliza iControl REST para capturar un snapshot JSON de la configuración, analiza sus referencias sin conexión, cruza los destinos de GSLB con los RAW originales de F5Audit LTM y genera un Excel o CSV para revisión de cleanup. No altera el estado de los F5.

**Regla de seguridad:** ningún comando `tmsh` se ejecuta; todos los comandos de cambio en el reporte llevan `NOT RUN:`. Un `Verdict`, una IP en FreedIP o una celda amarilla **nunca** constituyen autorización para borrar. Todas las aprobaciones inician en `PENDING`.

## Nuevo: modo `diagram` para mapear la topología (v0.5.3)

**Mejora v0.5.4:** el diagrama abre en **Focused View** y solo presenta un Wide IP y sus dependencias. El explorador de servicios pagina 25 Wide IPs por pantalla, el buscador enfoca por FQDN/IP/Server/Data Center, y `Overview` permite revisar todo el inventario con paginación. Para objetos compartidos, `Show Dependencies` permite saltar a otros Wide IPs asociados. Se conserva todo el RAW, Excel, CSV, JSON y el modo de auditoría de solo lectura.

Desde un RAW existente, sin nueva conexión al F5:

```powershell
f5auditdns diagram --from-raw ".\DNS_RAW" --ltm-raw-dir ".\LTM_RAW" -o ".\GSLB_Topology"
```

Genera `gtm_topology.json` y un HTML interactivo con mapas por partición, estados, dependencias, reglas y monitores. Consulta [docs/DIAGRAM_GUIDE_ES.md](docs/DIAGRAM_GUIDE_ES.md). El modo sigue siendo READ ONLY.

## 1. Arquitectura y conceptos

```text
Wide IP → GSLB Pool → Pool Member → GSLB Server → GSLB Virtual Server
                                                  ↓
                                   Destination IP + Port + Route Domain
                                                  ↓
                                   RAW opcionales de uno o más F5 LTM
```

Un GSLB Virtual Server vive **dentro de un `gtm server`**; no es un objeto `ltm virtual`. El miembro de un pool GSLB referencia al VS GSLB, no a un nodo backend de LTM. Un VS puede estar referenciado por varios pools. Presencia en configuración, salud, referencias y tráfico efectivo son evidencias distintas.

## 2. Instalación

En PowerShell, dentro del proyecto:

```powershell
py -m pip install .
py -m f5auditdns --version
py -m f5auditdns --help
```

Para pruebas y desarrollo:

```powershell
py -m pip install -e ".[dev]"
py -m pytest -q
```

Dependencias: `requests` e `openpyxl`. `pytest` es opcional y se utiliza en desarrollo. Si instalas desde una rama local, no confundas la versión instalada con la publicada en PyPI.

## 3. Comandos y opciones

### Validar permisos REST

```powershell
f5auditdns validate -ho 192.0.2.20 -u auditor
f5auditdns validate -ho dns01.example.test -u auditor --insecure
```

`-ho` acepta IP de administración o FQDN. `-u` indica el usuario. La contraseña se solicita sin mostrarse, salvo que uses `-p` o la variable `F5AUDITDNS_PASSWORD`. La validación TLS está activa por defecto; `--insecure` se debe reservar para entornos autorizados con certificados no verificables.

### Recolectar el RAW DNS

```powershell
f5auditdns collect -ho dns01.example.test -u auditor
f5auditdns collect -ho 192.0.2.20 -u auditor -o .\dns_raw
f5auditdns collect -ho dns01.example.test -u auditor --scope core --no-stats -o .\dns_config
```

Sin `-o`, crea una carpeta única `f5auditDNS_raw_<hostname>_<YYYYMMDD_HHMM>`. `--scope core` limita los datasets a los objetos principales; `all` (predeterminado) incluye reglas, monitores, topología y auxiliares. `--no-stats` omite estados operativos/counters; **no** equivale a marcar los servicios offline. Los errores de API quedan documentados en `Collection Health`.

### Analizar el RAW sin conectarse al BIG-IP

```powershell
f5auditdns analyze --from-raw .\dns_raw -o .\DNS_Audit.xlsx

f5auditdns analyze `
  --from-raw ".\dns_raw" `
  --ltm-raw-dir ".\ltm_raws" `
  -o ".\DNS_LTM_Correlation.xlsx"
```

`--from-raw` lee el snapshot DNS, `--ltm-raw-dir` busca recursivamente RAW originales de F5Audit LTM y `-o` establece el Excel. Puedes repetir `--ltm-raw-dir` para varias carpetas o utilizar `--ltm-raw GSLB_SERVER=PATH` para una correspondencia explícita. `--format csv` crea archivos CSV individuales.

El flag **`--ltm-coverage-complete`** es una declaración del operador de que incluyó **todos los LTM relevantes**. No comprueba por sí mismo la cobertura, no significa que la VIP esté retirada y no aprueba cambios. La diferencia máxima entre timestamps es 48 horas por defecto (`--max-snapshot-gap-hours`).

### Buscar un solo Virtual Server y resaltarlo

```powershell
f5auditdns analyze `
  --from-raw ".\dns_raw" `
  --virtual-server "vs_app" `
  -o ".\VS_Resaltado.xlsx"
```

Para evitar colisiones entre GSLB Servers, usa el identificador completo:

```powershell
f5auditdns analyze --from-raw ".\dns_raw" `
  --virtual-server "/Common/GDL-F5:/Common/vs_app" `
  -o ".\VS_Especifico.xlsx"
```

`--vs` es un alias de `--virtual-server`. Para buscar cualquier objeto, pool, Wide IP, nombre o IP utiliza `--object` (alias `--search`). Ambos flags aceptan repeticiones.

### Buscar una lista desde TXT, CSV o Excel

```powershell
f5auditdns analyze `
  --from-raw ".\DNS_RAW" `
  --ltm-raw-dir ".\LTM_RAW" `
  --file ".\freed_ips.txt" `
  -o ".\F5DNS_Resaltado.xlsx"
```

`--file` acepta `.txt`, `.csv` y `.xlsx`, lee varias columnas y pestañas y admite varias apariciones del flag. Ignora encabezados comunes y deduplica criterios. Puedes mezclar nombres de Virtual Servers, nombres completos de objetos, IPs, e IP:puerto/Route Domain.

**Resultado:** conserva todas las hojas y datos; solo resalta **celdas de identidad/destino que coinciden** en amarillo. La nueva pestaña `Search Results` indica el criterio, hoja, fila, columnas, fuente y estado `FOUND`/`NOT FOUND`. Las coincidencias no se convierten en objetos eliminables ni modifican `Verdict` o `Approval Status`. Si no pasas criterios de búsqueda, no aparece esta hoja.

La coincidencia de `192.0.2.4` **no** identifica `192.0.2.42`. Una búsqueda por `192.0.2.42%3:8443` requiere el puerto y Route Domain indicados. Un nombre corto de VS puede coincidir con varios objetos: utiliza el nombre compuesto para acotar la búsqueda.

**Actualizado:** `--file` resalta amarillo y, si contiene IPs válidas, las incluye como **evidencia NO aprobada para simular cleanup**. `--search-only` conserva el uso de resaltado exclusivo. `--freed-ip-file` permite aportar más IPs. Los valores de VS/pool en la lista solo se resaltan.

### FreedIP y simulación de cleanup

```powershell
f5auditdns analyze `
  --from-raw ".\dns_raw" `
  --ltm-raw-dir ".\ltm_raws" `
  --file ".\freed_ips.txt" `
  -o ".\DNS_Cleanup_Resaltado.xlsx"
```

FreedIP admite TXT/CSV/XLSX y varias columnas de IP. Las marcas **no certifican la decomisión**; una IP sola se cataloga como `IP ONLY - REVIEW`. `Pool Impact` calcula un escenario de remoción hipotético; deja `Approval Status` en `PENDING`. Un pool vacío aún podría depender de Wide IPs, Last Resort Pools, iRules, DR, topología o descubrimiento automático.

## 4. Hojas del Excel

| Pestaña | Para qué sirve |
| --- | --- |
| Summary | Conteos, estados, calidad de captura y métricas |
| Wide IP Findings | Wide IPs, reglas, pools directos y Last Resort |
| GSLB Pool Findings | Pools, miembros, health, métodos y referencias |
| Pool Members | Cada miembro por pool; destino, LTM, referencias y checks |
| GSLB Servers | Servidores GSLB, Data Center, dependencias y VS |
| GSLB Virtual Servers | VS definidos, IP, puerto, Route Domain, monitor y LTM |
| Data Centers | Data Centers, GSLB Servers y dependencias |
| DNS Chains | Cadena Wide IP → Pool → Member → Server → VS |
| Cleanup Candidates | Candidatos conservadores sin aprobación |
| LTM Inventories | RAW LTM usados, timestamps, roles HA, cobertura |
| Manual Review | Inconsistencias y relaciones que requieren inspección |
| Auxiliary Inventory | Monitores, iRules, listeners, topology y prober pools |
| Collection Health | Resultado de cada consulta iControl REST |
| Reference Map | Grafo de relaciones en ambas direcciones y vacíos |
| Object Inventory | Todos los objetos recolectados, incluso sin cadena DNS |
| Pool Impact | Simulación de members marcados/restantes, sin ejecutar cambios |
| Cleanup Procedure | Procedimiento ordenado de checks/cambio/rollback como referencia |
| FreedIP (opcional) | Inventario de IPs decomisionadas como evidencia no aprobada |
| Search Results (opcional) | Coincidencias por celda y términos no encontrados |

Las primeras 13 hojas se conservan en su orden original. Sin lista FreedIP ni búsqueda hay 17 hojas. Con FreedIP hay 18, con búsqueda hay 18; con ambas hay 19.

## 5. Interpretar los hallazgos

- `IN USE`: hay dependencias o una VIP LTM sigue registrada; **no borrar**.
- `MANUAL REVIEW`: información conflictiva, no concluyente o dependencias posibles.
- `UNRELIABLE`: faltan datos de inventario, permisos o relación unívoca.
- `OFFLINE (decommission candidate)`: candidato bajo reglas conservadoras; no es un permiso de eliminación.
- `ORPHAN`: pool sin referencias directas tras comprobaciones estrictas; revisar iRules, fallback y DR.
- `UNKNOWN` es un estado reportado; `NOT OBSERVED` significa que falta un estado usable en el snapshot.
- `ADDRESS_PRESENT_DIFFERENT_NAME`: la IP y puerto están en LTM bajo otro nombre.
- `IP_PRESENT_DIFFERENT_PORT`: la IP existe, pero **no** se comprobó el mismo servicio.
- `NOT_FOUND_IN_SCANNED_LTMS`: no está en los inventarios revisados; no demuestra ausencia global.

Los contadores de `/stats` son acumulados: un valor sin incremento medido entre capturas no es prueba de falta de tráfico. Los contadores de HA Active/Standby no se suman automáticamente.

## 6. Seguridad y rollback

El programa realiza llamadas GET de lectura y un POST exclusivamente para obtener token de acceso, no ejecuta comandos `tmsh`. Los comandos de `Delete`, `Create`, `Modify`, precheck y postcheck se guardan como referencias **`NOT RUN:`**. Cuando falta configuración fiel de `tmsh list ... all-properties`, se muestra **`ROLLBACK INCOMPLETE`**; jamás reconstruir propiedades no observadas o inventar monitores, ratios, member order, dependencias o valores no predeterminados.

No publiques RAW reales, Excel de producción, tokens, credenciales ni nombres/IPs confidenciales en GitHub, PyPI, issues o capturas compartidas. Los ejemplos utilizan bloques IP documentales y nombres ficticios. No se puede garantizar compatibilidad exacta de todas las rutas REST/propiedades `tmsh` entre versiones TMOS sin pruebas de laboratorio.

## 7. Ejemplos y mantenimiento

Generar un Excel con fixtures ficticios, sin conectar ningún F5:

```powershell
f5auditdns analyze --from-raw .\examples\raw_cleanup_simulado `
  --ltm-raw-dir .\examples\ltm_raws_multi_simulado `
  --virtual-server vs_app --file .\examples\decommissioned_ips_SIMULATED.txt `
  -o .\DNS_Ejemplo_Resaltado.xlsx
```

Para compilar y validar el paquete:

```powershell
py -m pytest -q
py -m pip install --upgrade build twine
py -m build
py -m twine check dist/*
```

La publicación a TestPyPI y PyPI se realiza **solo después** de revisar el código, ejecutar las pruebas y validar el comportamiento contra TMOS reales. Consulta [Guía de publicación (ES)](PUBLISHING_GITHUB_ACTIONS_ES.md), [Reference Engine (ES)](REFERENCE_ENGINE_ES.md) y [English user guide](USER_GUIDE_EN.md).

## v0.6.0 — Recuperación TMSH y planes TXT

Consulta read-only de las propiedades originales mediante `f5auditdns backup-tmsh -ho dns01.example.test -u auditor -o .\DNS_TMSH_Backup`.

Después genera los comandos de rollback y el procedimiento de cambio:

```powershell
f5auditdns analyze --from-raw ".\DNS_RAW" `
  --tmsh-backup-dir ".\DNS_TMSH_Backup" `
  --approval-file ".\Approved_Changes.txt" `
  --procedure-txt ".\Cleanup_Procedure.txt" `
  -o ".\F5DNS_Cleanup.xlsx"
```

Formato TXT de aprobaciones:

```text
APPROVED|MEMBER|a|/Common/pool_app|/Common/GDL-F5:/Common/vs_app|CHG-12345
APPROVED|POOL|a|/Common/pool_app||CHG-12345
```

Los comandos de consulta y recuperación son referencias `NOT RUN`; el proyecto NO ejecuta cambios. Un respaldo incompleto o sensible no se considera rollback verificado. No publicar en GitHub los respaldos reales ni los TXT con información de producción.
