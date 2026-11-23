# GitHub update texts — F5AuditDNS v0.5.2

> Development only. Do not publish a GitHub Release before review and CI; the
> existing GitHub Release workflow automatically publishes to PyPI.

## GitHub Desktop — Summary (English)

```text
F5AuditDNS v0.5.2 - Single TXT file for highlighting and cleanup simulation
```

## GitHub Desktop — Description (English)

```text
- Extend analyze --file to accept a single TXT/CSV/XLSX list for yellow cell highlighting and unapproved FreedIP / Pool Impact simulation.
- Parse only valid IP and endpoint entries as simulated decommission evidence; virtual-server and object names remain search-only.
- Add --search-only to retain the previous highlight-only behavior for --file.
- Preserve --freed-ip-file as optional additional evidence and deduplicate repeated IPs.
- Keep original audit verdicts, Approval Status=PENDING, 13 core worksheets, reference map, impact analysis and LTM evidence unchanged.
- Fix a per-member Cleanup Readiness source-selection issue.
- Update bilingual English/Spanish README, CLI help, user guides and regression tests.
- Maintain READ ONLY operation; all tmsh modification and rollback commands are NOT RUN references.
```

## GitHub Desktop — Resumen (Español)

```text
F5AuditDNS v0.5.2 - Un TXT para resaltar y simular cleanup
```

## GitHub Desktop — Descripción (Español)

```text
- --file acepta una lista TXT/CSV/XLSX para resaltar en amarillo y simular impacto en FreedIP y Pool Impact.
- Solo IPs y endpoints válidos sirven como evidencia de simulación. Los nombres de VS y otros objetos solo se buscan.
- Nuevo --search-only para desactivar la simulación y mantener la búsqueda visual anterior.
- Se conserva --freed-ip-file y se evitan IPs duplicadas cuando se emplean ambos flags.
- Se mantienen los veredictos, Approval Status=PENDING y las 13 hojas originales con el motor completo de referencias y correlación LTM.
- Corrección de Cleanup Readiness por cada miembro y actualización bilingüe de guías, ayuda y pruebas.
- READ ONLY: comandos tmsh Delete/Create/Modify/Rollback solo como NOT RUN.
```

## Pull Request Title

```text
feat: combine offline TXT search and conservative FreedIP simulation (v0.5.2)
```

## Release Notes — English (ONLY AFTER CI + TMOS REVIEW)

# F5AuditDNS v0.5.2 — Unified Offline Search and Impact Simulation

Use a single `--file freed_ips.txt` with existing DNS/LTM RAW snapshots to
highlight matching IP/endpoint cells yellow and generate unapproved FreedIP and
Pool Impact what-if analyses. `Search Results` reports exact matches. `--search-only`
keeps previous highlight-only behavior. Names are never treated as decommission
proof. All original sheets, health/LTM evidence, and READ ONLY protections remain.

## Notas de versión — Español (SOLO DESPUÉS DE PRUEBAS)

# F5AuditDNS v0.5.2 — Búsqueda y simulación en un solo archivo TXT

Con `--file freed_ips.txt` y RAW existentes se resaltan IPs/endpoints en amarillo
y se calculan simulaciones NO aprobadas en FreedIP/Pool Impact. Search Results
identifica coincidencias exactas; `--search-only` conserva el resaltado sin
simular. Nombres de Virtual Servers y objetos no son prueba de decomisión.
Se mantienen las hojas anteriores, estados, evidencia LTM y READ ONLY.
