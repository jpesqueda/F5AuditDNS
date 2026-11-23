# Motor de referencias y cleanup v0.5.2 — Notas de ingeniería (ES)

[English](REFERENCE_ENGINE_EN.md) · [Guía de uso](USER_GUIDE_ES.md)

## Datos origen y trazabilidad

Los snapshots JSON guardan configuración en `gtm_wideip_*`, `gtm_pool_*`, `pool_members::<tipo>::<pool>`, `gtm_server`, `server_virtuals::<server>` y datasets auxiliares; los estados y contadores `/stats` originales se conservan. La v0.5.2 **no requiere modificar `collector.py`** para buscar o elaborar referencias, porque trabaja exclusivamente con RAW existentes.

Las reglas de la v0.4.0 de `analyze()` y `enrich_cleanup()` siguen produciendo la salud, correlaciones LTM y veredictos. Luego `build_reference_report()` amplía filas existentes sin descartar columnas.

Las referencias estáticas de Wide IP provienen de `wideip_pools::*` y `wideip_pools_cname::*`; `lastResortPool` se trata por separado como `LAST RESORT`. La falta de una subcolección implica evidencia **desconocida**, no lista vacía.

## Pools, miembros y Virtual Servers

Los miembros de cada pool se obtienen de `pool_members::<record>::<fullPath>`. Antes de simular una eliminación, se revisa `endpoint_results`. Si faltan datos, se muestra `INVENTORY INCOMPLETE - NO SIMULATION` y no se inventa el número de miembros restantes.

Para cada GSLB Virtual Server se incluyen **todas** las referencias por Pool Member y el `gtm server` padre. Se documentan `virtualServerDiscovery`, `dependsOn`, monitores y posibles referencias dinámicas; un VS compartido exige retirar primero **todas** las referencias aprobadas y verificar posible autodescubrimiento.

## FreedIP: evidencia y simulación

El importador interpreta TXT, CSV y XLSX y separa IP, puerto y route domain cuando están presentes. Una coincidencia de IP sola equivale a `IP ONLY - REVIEW`, no a decomisión demostrada. Los miembros marcados, contadores y las acciones de Pool Impact constituyen una **simulación no aprobada**; no cambian `Verdict`, `Cleanup Candidates` ni `Approval Status=PENDING`.

## Búsqueda y resaltado en amarillo

`search.py` recibe nombres o direcciones directamente desde `--virtual-server`, `--object` o de TXT/CSV/XLSX con `--file`. El exportador conserva todas las pestañas y resalta únicamente celdas de identidad/destino que coincidan. `Search Results` conserva el criterio, su fuente, hoja, fila, columnas y estado encontrado/no encontrado. La IP no coincide por prefijo; los endpoints explícitos validan puerto y route domain. Un identificador `SERVER:VS` exige correspondencia con ese servidor cuando puede comprobarse.

Ahora `--file` alimenta una simulación NO aprobada para IPs válidas, mientras que VS/nombres solo resaltan. `--search-only` omite la simulación; ninguna búsqueda modifica Verdict ni Approval Status. Las columnas de comandos y notas libres no se modifican ni se evalúan como nombres de objetos.

## Rollback y comandos

Los datos REST sanitizados no pueden garantizar reconstruir exactamente una configuración que depende de atributos predeterminados, herencia, orden, monitores, particiones o secretos. Por ello todos los ejemplos de cambio son texto `NOT RUN:`; en ausencia de un `tmsh list ... all-properties` completo se declara `ROLLBACK INCOMPLETE`. Para una operación aprobada se exige backup validado y comandos inversos inspeccionados manualmente.

## Confidencialidad, pruebas y publicación

Nunca publicar JSON RAW de producción, Excel de auditoría real, IPs/FQDN privados, UCS, credenciales, tokens ni capturas de equipo. Los fixtures del repositorio utilizan direcciones documentales y dominios ficticios. Los tests cubren uso de RAW antiguos, comparaciones LTM, referencias de Wide IP directas y Last Resort, entradas FreedIP, búsqueda exacta y no coincidencias parciales, y el cumplimiento READ ONLY.

La validación contra versiones TMOS reales se debe realizar antes de lanzar PyPI, especialmente cuando hay discovery, iRules o topología dinámica.
