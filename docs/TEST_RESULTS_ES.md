# F5AuditDNS v0.5.4 — Resumen de pruebas

- **145 pruebas de pytest aprobadas localmente**, incluidas las 136 de la v0.5.3.
- Prueba visual de Chromium sin interfaz: simulación de 295 Wide IPs, paginación de 25 servicios, búsqueda, selector Focused/Overview, dependencias compartidas y grupos paginados. Sin errores JavaScript.
- Sintaxis JavaScript verificada con Node.js; wheel y sdist compilados.
- Matriz GitHub Actions Windows y Linux (Python 3.9 y 3.12): pendiente al preparar el paquete.
- El código no realiza operaciones de escritura en BIG-IP ni utiliza datos de producción en los tests.

### v0.6.0

164 pruebas locales aprobadas (145 anteriores + 19 nuevas). Se validó la reconstrucción por bloques TMSH, el TXT de cambios controlados y el bloqueo de pools con dependencias. La captura SSH se simuló con mocks: **no se ha validado contra un BIG-IP real** ni se ha probado recuperación real en TMOS.
