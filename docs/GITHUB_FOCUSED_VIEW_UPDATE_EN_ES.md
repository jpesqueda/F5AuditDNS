# GitHub commit / release text for v0.5.4

## Commit Summary

F5AuditDNS v0.5.4 - Focused GSLB topology explorer

## Commit Description

- Make Focused View the default: show one Wide IP dependency chain at a time instead of thousands of expanded nodes.
- Add 25-item paginated Service Explorer and paginated branch expansion in Overview mode.
- Auto-focus search matches by FQDN, IP, GSLB VS, Server or Data Center; retain partition and status filters.
- Add Show Dependencies navigation for objects used by multiple Wide IPs.
- Preserve all RAW datasets, canonical topology JSON, Excel/CSV auditing, TMOS health evidence and READ ONLY behavior.
- Add bilingual docs and nine focused-view regression tests (145 local tests total), plus synthetic browser stress validation.

## Release Notes (English)

### F5AuditDNS v0.5.4 — Focused GSLB Topology

**What's new**
- Focused View opens by default with a readable single Wide IP chain.
- Service Explorer offers FQDN/IP/VS/Server/DC search and 25 services per page.
- Overview retains the complete multi-partition inventory, with bounded paginated exploration.
- Show Dependencies links objects to other referencing Wide IPs.
- No new collector operation, no changes to Excel/CSV or canonical JSON.

**Security:** READ ONLY; `tmsh` commands are `NOT RUN` references. No production data included.

**Validation:** 145 local tests pass; release only after Windows and Linux CI pass.

## Notas de versión (Español)

### F5AuditDNS v0.5.4 — Explorador de topología enfocado

- Nueva vista predeterminada **Focused View**: un Wide IP y sus dependencias a la vez.
- Explorador paginado de 25 servicios; búsqueda por FQDN, IP, VS, Server y Data Center.
- **Overview** conserva el inventario de todas las particiones con expansión y páginas controladas.
- **Show Dependencies** permite ver otros Wide IPs que utilizan los mismos recursos.
- Se conservan los RAW originales, los reportes Excel/CSV, el JSON completo y la seguridad de solo lectura.
- 145 pruebas locales aprobadas; publicación solamente después de CI en verde.
