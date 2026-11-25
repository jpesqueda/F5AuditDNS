# Contexto del proyecto F5AuditDNS v0.5.4 (Español)

- Se mantiene el código de la v0.4.0 y las mejoras v0.5.0; no se reescribe el cliente REST ni el colector.
- Solo lectura: GET para inventario y estadísticas, POST de autenticación para token, análisis RAW offline; comandos `tmsh` solo `NOT RUN`.
- Se mantienen las 13 hojas originales, Reference Map, Object Inventory, Pool Impact, Cleanup Procedure y FreedIP opcional.
- `freedip.py` recibe TXT/CSV/XLSX de IPs decomisionadas como evidencia para simulación, sin autorización automática.
- `reference_engine.py` amplía referencias y dependencias después de análisis de salud/LTM, sin borrar columnas.
- `search.py` permite buscar VS, objetos e IPs desde línea de comandos o archivo TXT/CSV/XLSX. Las celdas de destino/identidad coincidentes se resaltan en amarillo; Search Results es opcional.
- `--file` resalta y aporta IPs a la simulación con aprobación PENDING; `--search-only` solo busca y `--freed-ip-file` permite evidencia adicional. Verdict no cambia.
- Rollback exacto requiere backup externo; REST no garantiza recuperar todos los atributos originales.
- Solo fixtures ficticios; no subir RAW ni credenciales de producción. Se recolecta un F5 DNS por ejecución.
- Versión 0.5.4 en desarrollo, v0.5.3 publicada en PyPI. Publicar 0.5.4 solo con CI aprobada.

- `diagram.py`, `diagram_html.py` y `diagram_mock.py` producen grafos offline multi-partición y un HTML interactivo sin nuevos endpoints de recolección ni cambios de configuración.

- v0.5.4 agrega Focused View, Service Explorer y paginación (25 elementos), sin modificar los RAW ni el JSON completo.
