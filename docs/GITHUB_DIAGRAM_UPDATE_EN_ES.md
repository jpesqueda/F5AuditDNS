# GitHub Desktop commit — F5AuditDNS v0.5.3 (EN / ES)

## Summary

F5AuditDNS v0.5.3 - Offline multi-partition GSLB topology diagram

## Description

- Add `f5auditdns diagram --from-raw DIR` and alias `f5auditdns --diagram --raw DIR`, preserving all existing collection, analysis, Excel, CSV and cleanup functionality.
- Build a global, fullPath-indexed GSLB reference graph covering Wide IPs, direct and Last Resort Pools, Pool Members, GSLB Virtual Servers, Servers, Data Centers, health monitors, iRules, Topology and auxiliary inventory.
- Resolve cross-partition references correctly and detect shared Virtual Servers referenced by multiple GSLB Pools.
- Generate portable `gtm_topology.json` and interactive `f5_dns_topology.html` with horizontal collapsible tree, Bézier connections, zoom/pan, partition and status filters, search, and a right-side object inspector.
- Keep observed versus derived health distinct. Surface iQuery only when supported by explicit collected evidence; never infer connectivity loss from missing stats.
- Add conservative orphan-review categories that account for missing catalogs and potential dynamic references.
- Provide `--mock` with synthetic devices, optional LTM RAW evidence, `--device-label`, `--no-raw-inspector`, and `--d3-js` for embedding a locally provided D3.js v7 bundle.
- Provide an offline SVG rendering fallback when the D3 v7 library is not embedded/available.
- Add English/Spanish diagram documentation, source package support, regression tests, and a minimal requirements.txt.
- Maintain READ ONLY operation. All change-related tmsh commands remain NOT RUN references. No production data or secrets are included.

## Descripción en español

- Nuevo modo de diagrama desde RAW existentes, sin repetir collect y sin modificar el funcionamiento de las auditorías Excel.
- Mapa de relaciones GSLB multi-partición con Wide IP, Pools, Pool Members, VS GSLB, GSLB Servers, Data Centers y monitores.
- Referencias a objetos de /Common desde otras particiones, detección de VS en varios pools y clasificación conservadora de dependencias potenciales.
- Exportación HTML/JSON con árbol interactivo, búsquedas, colores de estados, zoom y panel inspector.
- Los estados derivados no se confunden con telemetría real; no se infiere una caída iQuery sin evidencia explícita.
- Datos simulados con `--mock`, guías EN/ES y pruebas automatizadas.
- Seguridad READ ONLY y comandos de referencia `NOT RUN`; no se publican datos sensibles.

## Pull Request title

feat(diagram): add offline GSLB topology explorer and cross-partition reference graph

## Release notes

### v0.5.3 — Diagram Mode / Modo Diagrama

After collecting a BIG-IP DNS snapshot, generate an interactive, navigable GSLB topology entirely from local RAW data. The new command integrates with existing F5AuditDNS audit and optional F5Audit LTM evidence without making any device changes.

Después de recolectar el RAW, crea un diagrama interactivo de GSLB directamente desde los datos guardados, conservando toda la auditoría existente y sin conectarte de nuevo al F5. Todas las referencias de cleanup son informativas y requieren revisión.

```powershell
f5auditdns diagram --from-raw ".\DNS_RAW" --ltm-raw-dir ".\LTM_RAW" -o ".\GSLB_Topology"
```

Release only after the CI matrix passes on Windows/Ubuntu and target TMOS snapshots are validated. Do not publish to PyPI merely by committing these changes.
