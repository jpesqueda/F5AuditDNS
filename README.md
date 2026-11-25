# F5AuditDNS — BIG-IP DNS/GSLB Audit & Cleanup Review

**Development version 0.5.4** · Python 3.9+ · Windows / Linux / macOS · **READ ONLY**

**Language / Idioma:** [English](#english) | [Español](#español)

[Source / Código](https://github.com/jpesqueda/F5AuditDNS) · [English documentation](https://github.com/jpesqueda/F5AuditDNS/blob/main/docs/USER_GUIDE_EN.md) · [Documentación en español](https://github.com/jpesqueda/F5AuditDNS/blob/main/docs/USER_GUIDE_ES.md)

---

## English

### New in v0.5.4 — Focused View for large GSLB inventories

The **diagram HTML now opens in Focused View**, showing one Wide IP and its dependency chain instead of expanding every object. An offline **Service Explorer** lists 25 Wide IPs per page, with partition/status filters and instant FQDN, destination IP, GSLB Server or Data Center search; selecting a result focuses the map. Child groups with more than 25 entries are paginated, while `Overview` preserves the complete multi-partition inventory and offers bounded expansion. The inspector provides **Show Dependencies**, linking shared objects to all referencing Wide IPs. The full topology JSON is unchanged. The browser needs no server and never contacts BIG-IP.

```powershell
py -m pip install --upgrade f5auditdns==0.5.4
f5auditdns diagram --from-raw ".\DNS_RAW" --ltm-raw-dir ".\LTM_RAW" -o ".\GSLB_Topology" --open
```

For a complete explanation, see [Diagram Guide EN](docs/DIAGRAM_GUIDE_EN.md) / [Guía Diagram ES](docs/DIAGRAM_GUIDE_ES.md).

### New: interactive GSLB topology diagram (v0.5.3)

After `collect`, run `f5auditdns diagram --from-raw ".\DNS_RAW" -o ".\GSLB_Topology"`. The alias `f5auditdns --diagram --raw ".\DNS_RAW"` also works. It generates `gtm_topology.json` and `f5_dns_topology.html`, including cross-partition connections, health evidence and conservative orphan review. For a device-free demo use `f5auditdns diagram --mock -o .\Demo`. Full instructions: [Diagram guide (EN)](docs/DIAGRAM_GUIDE_EN.md).

For a self-contained HTML **embedding the actual D3.js v7 bundle**, supply `--d3-js .\d3.v7.min.js`. Without it, the HTML is still fully interactive offline using the included SVG renderer; when served over HTTP(S), it may use D3 from the official CDN. No source RAW files or passwords are sent to a web service by diagram generation.

### What does F5AuditDNS do?

It collects BIG-IP DNS/GSLB configuration through iControl REST into offline JSON RAW snapshots, reconstructs **Wide IP → GSLB Pool → Pool Member → GSLB Server → GSLB Virtual Server → Destination IP/Port/Route Domain** relationships, optionally compares endpoints with any number of F5Audit LTM RAW snapshots, and generates full Excel or CSV review reports. It does **not** change BIG-IP configuration.

The 13 original audit worksheets remain. The reference engine adds **Reference Map**, **Object Inventory**, **Pool Impact** and **Cleanup Procedure**. Optional **FreedIP** and **Search Results** tabs appear only when their corresponding inputs are provided. Original status, statistics, LTM evidence and cleanup annotations remain in the workbook.

### Install

```powershell
py -m pip install f5auditdns
f5auditdns --version
f5auditdns --help
```

To install a **development archive before PyPI publication**, unzip it and run `py -m pip install .` from the project directory instead. A development version may not be available from PyPI yet.

### 1. Validate and collect (live, read-only)

```powershell
f5auditdns validate -ho 192.0.2.20 -u auditor
f5auditdns collect -ho dns01.example.test -u auditor
f5auditdns collect -ho dns01.example.test -u auditor -o ".\DNS_RAW"
```

The password is securely prompted. TLS verification is enabled by default; `--insecure` is for authorized exception/lab scenarios. `collect` includes REST `/stats` unless `--no-stats` is given. Without `-o`, a hostname/timestamp snapshot folder is created automatically.

### 2. Analyze DNS and LTM RAW (offline)

```powershell
f5auditdns analyze `
  --from-raw ".\DNS_RAW" `
  --ltm-raw-dir ".\LTM_RAW" `
  -o ".\F5DNS_Cleanup.xlsx"
```

This reuses existing RAWs without contacting BIG-IP. `--ltm-coverage-complete` is an **operator assertion** of complete LTM snapshot coverage, not an automatic validation or permission to delete.

### 3. Search a Virtual Server or list; highlight matching cells yellow

```powershell
# Search one VS by short name:
f5auditdns analyze --from-raw ".\DNS_RAW" --virtual-server "vs_app" -o ".\VS_Search.xlsx"

# Search one exact server/VS pair:
f5auditdns analyze --from-raw ".\DNS_RAW" `
  --virtual-server "/Common/GDL-F5:/Common/vs_app" -o ".\VS_Search.xlsx"

# Search IPs, names, endpoints from a TXT, CSV, or multi-column XLSX:
f5auditdns analyze `
  --from-raw ".\DNS_RAW" `
  --ltm-raw-dir ".\LTM_RAW" `
  --file ".\freed_ips.txt" `
  -o ".\F5DNS_Highlighted.xlsx"
```

`--vs` aliases `--virtual-server`; `--object` (alias `--search`) accepts other GSLB names or IPs. These options can be repeated. The **full report is preserved**, relevant identity/destination cells are colored **yellow**, and `Search Results` records matches and missing terms. IP matching respects exact addresses, optional port and route domain; mere substring matches are rejected. Search **never changes cleanup decisions**.

`--file` now performs **both tasks with one input**: yellow highlights plus **unapproved FreedIP/Pool Impact simulation for valid IPs**. VS/object names are highlighted only. For the former search-only behavior use `--file FILE --search-only`. `--freed-ip-file` remains available for explicit additional evidence. Neither changes `Verdict` or `Approval Status=PENDING`.

### 4. Evaluate decommissioned IPs (simulation only)

```powershell
f5auditdns analyze --from-raw ".\DNS_RAW" `
  --ltm-raw-dir ".\LTM_RAW" `
  --file ".\freed_ips.txt" `
  -o ".\DNS_Cleanup_Reviewed.xlsx"
```

A plain IP is never proof of endpoint decommission. `Pool Impact` is hypothetical; a simulated empty pool still requires validation of Wide IPs, Last Resort Pools, iRules, DR and topology. `Approval Status` defaults to `PENDING`.

### 5. Safety & report interpretation

All `tmsh` Delete/Modify/Create/Rollback commands in the report are **`NOT RUN` references** and are **never executed**. Exact rollback is not guaranteed without the saved original `tmsh list ... all-properties` / approved full backup; the tool reports `ROLLBACK INCOMPLETE` when appropriate. `Health=NOT OBSERVED` means missing operational evidence, not downtime; `NOT_FOUND_IN_SCANNED_LTMS` is not proof of global absence. Use approved procedures and verify on the live BIG-IP before cleanup.

**Full instructions:** [English user guide](https://github.com/jpesqueda/F5AuditDNS/blob/main/docs/USER_GUIDE_EN.md) · [Reference engine](https://github.com/jpesqueda/F5AuditDNS/blob/main/docs/REFERENCE_ENGINE_EN.md) · [GitHub Actions publishing](https://github.com/jpesqueda/F5AuditDNS/blob/main/docs/PUBLISHING_GITHUB_ACTIONS_EN.md)

---

## Español

### Nuevo en v0.5.4 — Vista enfocada para inventarios grandes

El visor `diagram` abre en **Focused View**, mostrando la cadena de un solo Wide IP en lugar de expandir toda la infraestructura. El **Service Explorer** muestra 25 Wide IPs por página, permite filtrar por partición y estado, buscar por FQDN, IP de destino, Server o Data Center y enfocar el resultado. `Overview` conserva el inventario completo con expansión limitada y paginada. En el inspector, **Show Dependencies** identifica los Wide IPs que comparten un mismo objeto. El JSON completo y el modo **READ ONLY** no cambian. Consulta [la guía en español](docs/DIAGRAM_GUIDE_ES.md).

```powershell
f5auditdns diagram --from-raw ".\DNS_RAW" -o ".\GSLB_Topology" --open
```

### Nuevo: diagrama interactivo de topología GSLB (v0.5.3)

Después de `collect`, ejecuta `f5auditdns diagram --from-raw ".\DNS_RAW" -o ".\GSLB_Topology"`. También funciona `f5auditdns --diagram --raw ".\DNS_RAW"`. Genera el JSON del grafo y un HTML con árbol horizontal, relaciones entre particiones, estados, referencias y revisión de posibles objetos sin uso conocido. Demo sin F5: `f5auditdns diagram --mock -o .\Demo`. Consulta la [Guía de diagramas (ES)](docs/DIAGRAM_GUIDE_ES.md).

Para incluir D3.js v7 dentro del HTML, utiliza `--d3-js .\d3.v7.min.js` con un archivo obtenido del proveedor. Sin él, el visor funciona offline mediante SVG; si lo abres desde HTTP(S), puede intentar usar el CDN oficial. Ningún modo de diagrama ejecuta modificaciones ni se conecta al F5 para consultar la captura.

### ¿Para qué sirve F5AuditDNS?

F5AuditDNS recopila por iControl REST la configuración de BIG-IP DNS/GSLB y crea snapshots **RAW JSON**. Reconstruye las relaciones **Wide IP → GSLB Pool → Pool Member → GSLB Server → GSLB Virtual Server → IP/Puerto/Route Domain**. Puede comparar los destinos contra cualquier cantidad de RAW originales de F5Audit LTM y genera un Excel o CSV para revisión de cleanup. **No modifica la configuración de los equipos.**

Se conservan las **13 hojas originales**, más **Reference Map**, **Object Inventory**, **Pool Impact** y **Cleanup Procedure**. Las hojas opcionales **FreedIP** y **Search Results** aparecen si se proporcionan sus entradas. Los estados, estadísticas, monitores, evidencias LTM y observaciones anteriores siguen disponibles.

### Instalación

```powershell
py -m pip install f5auditdns
f5auditdns --version
f5auditdns --help
```

Si la versión de desarrollo aún no está en PyPI, descomprime el ZIP del proyecto y ejecuta `py -m pip install .` dentro de la carpeta que contiene `pyproject.toml`.

### 1. Validar y recolectar (solo lectura)

```powershell
f5auditdns validate -ho 192.0.2.20 -u auditor
f5auditdns collect -ho dns01.example.test -u auditor
f5auditdns collect -ho dns01.example.test -u auditor -o ".\DNS_RAW"
```

Se solicita la contraseña de forma segura. La verificación TLS está activa por defecto; utiliza `--insecure` solo en casos autorizados. `collect` recupera estadísticas operativas salvo que se indique `--no-stats`. Sin `-o` crea una carpeta nueva con hostname y timestamp.

### 2. Analizar RAW DNS y LTM (offline)

```powershell
f5auditdns analyze `
  --from-raw ".\DNS_RAW" `
  --ltm-raw-dir ".\LTM_RAW" `
  -o ".\F5DNS_Cleanup.xlsx"
```

Reutiliza los RAW existentes sin conectar de nuevo a los F5. `--ltm-coverage-complete` es una **declaración del operador** de que están representados todos los LTM relevantes; no comprueba la cobertura ni autoriza cambios.

### 3. Buscar un Virtual Server o lista y pintar las celdas de amarillo

```powershell
# Un solo Virtual Server:
f5auditdns analyze --from-raw ".\DNS_RAW" --virtual-server "vs_app" -o ".\VS_Resaltado.xlsx"

# Virtual Server acotado a su GSLB Server:
f5auditdns analyze --from-raw ".\DNS_RAW" `
  --virtual-server "/Common/GDL-F5:/Common/vs_app" -o ".\VS_Resaltado.xlsx"

# Lista desde TXT, CSV o Excel (varias columnas):
f5auditdns analyze `
  --from-raw ".\DNS_RAW" `
  --ltm-raw-dir ".\LTM_RAW" `
  --file ".\freed_ips.txt" `
  -o ".\F5DNS_Resaltado.xlsx"
```

`--vs` es un alias de `--virtual-server`; `--object` (alias `--search`) busca pools, nombres, Wide IPs e IPs. Puedes repetir las opciones. El reporte **no se reduce ni se filtra**: únicamente se colorean **las celdas coincidentes en amarillo**. La hoja nueva **Search Results** indica términos encontrados y no encontrados, hoja, fila y columnas coincidentes. Las búsquedas de IP no aceptan coincidencias parciales ni confunden puerto o Route Domain. **Buscar no cambia los veredictos.**

`--file` ahora hace **ambas cosas con el mismo archivo**: resalta coincidencias en amarillo y considera las IPs válidas como **evidencia para simulación FreedIP/Pool Impact sin aprobación**. Los nombres de objetos o VS solo se buscan. Para buscar sin simular utiliza `--file ARCHIVO --search-only`. `--freed-ip-file` sigue disponible para evidencia adicional; ninguna opción modifica `Verdict` ni `Approval Status=PENDING`.

### 4. Simulación de cleanup con FreedIP

```powershell
f5auditdns analyze --from-raw ".\DNS_RAW" `
  --ltm-raw-dir ".\LTM_RAW" `
  --file ".\freed_ips.txt" `
  -o ".\F5DNS_Cleanup_Revision.xlsx"
```

Una IP sola **no** demuestra que se retiró el servicio. `Pool Impact` simula miembros marcados y restantes, pero no ejecuta acciones. Un pool hipotéticamente vacío exige revisar Wide IPs, Last Resort, iRules, DR y topología; `Approval Status` inicia en `PENDING`.

### 5. Seguridad e interpretación

Todos los comandos `tmsh` Delete/Modify/Create/Rollback se muestran como **`NOT RUN`** y **nunca se ejecutan**. Un rollback exacto necesita un respaldo real del objeto (`tmsh list ... all-properties`) o backup aprobado; si faltan propiedades, aparece `ROLLBACK INCOMPLETE`. `Health=NOT OBSERVED` es evidencia faltante, no estado caído. `NOT_FOUND_IN_SCANNED_LTMS` no significa ausencia confirmada en toda la infraestructura. Revisa dependencias y estado en vivo antes de un cambio.

**Documentación ampliada:** [Guía completa en español](https://github.com/jpesqueda/F5AuditDNS/blob/main/docs/USER_GUIDE_ES.md) · [Motor de referencias](https://github.com/jpesqueda/F5AuditDNS/blob/main/docs/REFERENCE_ENGINE_ES.md) · [Publicación en GitHub Actions](https://github.com/jpesqueda/F5AuditDNS/blob/main/docs/PUBLISHING_GITHUB_ACTIONS_ES.md)

---

**Security / Seguridad:** Fictional examples use documentation IP ranges and `example.test` hostnames. Do not upload production RAWs, credentials, tokens, screenshots or infrastructure inventories to GitHub or PyPI. / Los ejemplos usan direcciones documentales y nombres ficticios. No compartas RAW de producción ni datos críticos.

License / Licencia: MIT.
