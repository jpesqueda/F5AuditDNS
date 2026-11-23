# F5AuditDNS v0.5.2 — Resultados de pruebas (Español)

- **106 pruebas automáticas aprobadas** con datos completamente ficticios.
- Se conservan las pruebas de las versiones v0.4.0, v0.5.0 y v0.5.1.
- `--file` recibe TXT/CSV/XLSX, resalta amarillo e interpreta las IPs válidas como evidencia de simulación no aprobada en FreedIP y Pool Impact.
- `--search-only` evita la simulación. `--freed-ip-file` sigue disponible y las IPs repetidas se deduplican.
- Los nombres de VS y objetos solo se buscan; una IP con puerto diferente no se considera el mismo servicio.
- Las 13 hojas originales, cuatro adicionales, FreedIP y Search Results se mantienen (19 cuando aplican ambas opciones).
- `Verdict`, `Cleanup Candidates` y `Approval Status=PENDING` siguen sin alterarse por criterios de búsqueda o simulación.
- Wheel y distribución fuente construidos localmente mediante setuptools `build_meta` y Excel de ejemplo validado.
- No hubo conexión con dispositivos BIG-IP ni publicación PyPI. Comandos tmsh como referencia `NOT RUN`.

**Antes de publicar:** validar RAW anonimizados de la versión real TMOS, ejecutar GitHub Actions en Windows/Linux y `twine check`.
