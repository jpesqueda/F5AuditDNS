# Registro de cambios

## [0.5.2] — 20 noviembre 2026 (desarrollo, sin publicar)

- `analyze --file ARCHIVO` (TXT/CSV/XLSX) resalta celdas amarillas y simula impacto NO aprobado con IPs/endpoints válidos en FreedIP y Pool Impact.
- Los nombres de objetos/VS únicamente se resaltan; `--search-only` recupera el uso anterior exclusivamente visual.
- Se conserva `--freed-ip-file` como evidencia adicional; IPs duplicadas se procesan una sola vez.
- Se mantienen veredictos, Approval Status=PENDING, hojas originales, estadísticas, correlación LTM y comandos NOT RUN.
- Se corrige Cleanup Readiness por miembro y se amplían pruebas y documentación bilingüe.


## [0.5.1] — 20 noviembre 2026 (en desarrollo; no publicado)

- Nuevo `analyze --virtual-server NOMBRE` (alias `--vs`) y `--object NOMBRE` (alias `--search`) para localizar objetos en RAW existentes.
- Nuevo `--file ARCHIVO` repetible: listas TXT/CSV/XLSX con varias columnas y coincidencia exacta de IP, puerto y Route Domain. **No confundir** con `--freed-ip-file`, que aporta evidencia de IP decomisionada.
- Celdas de identidad/destino coincidentes resaltadas en amarillo; conserva el Excel completo y todos los veredictos.
- Pestaña opcional **Search Results** con criterio, origen, hoja, fila, columnas, FOUND / NOT FOUND.
- README bilingüe visible en PyPI, guías de uso, referencias técnicas y publicación GitHub Actions en ambos idiomas; `--help` con explicaciones en inglés y español.
- Pruebas automatizadas con datos ficticios; sin cambios en equipos ni publicación en PyPI.

## [0.5.0] — 20 noviembre 2026 (desarrollo)

- Conserva las 13 pestañas originales e incorpora Reference Map, Object Inventory, Pool Impact y Cleanup Procedure, más FreedIP opcional.
- Detecta Wide IPs directos y Last Resort, referencias de Virtual Server compartidas por pools y dependencias de servidores GSLB.
- Simula el retiro de miembros marcados sin aprobar cambios; rollback incompleto explícito y comandos `NOT RUN`.
- Admite RAW anteriores y comparación LTM por IP/puerto/Route Domain.

## [0.4.0] — 16 noviembre 2026

- Nuevas estadísticas operativas GSLB `/stats`, fuentes de salud, IP/puerto/Route Domain separados, y correlación mejorada con LTM.
- Diferencia estados `UNKNOWN` vs `NOT OBSERVED`, conserva health y estadísticas de conexiones LTM.

## [0.3.0] — 12 noviembre 2026

- Descubrimiento automático recursivo de RAW LTM, comparación de VIPs, flag `--ltm-coverage-complete`, referencias Delete/Rollback `NOT RUN`.
- Nuevas hojas LTM Inventories y verificación conservadora de candidates.

## [0.2.0–0.1.0] — 11 noviembre 2026

- Primeros prototipos de F5AuditDNS: validate/collect/analyze, inventario GSLB A/AAAA/CNAME/MX/NAPTR/SRV, RAW JSON, hojas Excel y comparación manual LTM.
- Carpeta automática de snapshot con hostname, timestamps, tests y comandos del CLI.
