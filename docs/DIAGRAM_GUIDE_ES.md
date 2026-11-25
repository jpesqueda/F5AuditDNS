# F5AuditDNS — Modo diagrama GSLB (v0.5.3)

**READ ONLY / SIN CONEXIÓN al analizar.** Es una extensión del recolector y analizador existentes de F5AuditDNS; no crea otro recolector con credenciales ni requiere un backend web.

## Uso recomendado

```powershell
# Ya tenemos el RAW del DNS.
f5auditdns diagram --from-raw ".\DNS_RAW" -o ".\GSLB_Topology"

# También soporta tu sintaxis corta.
f5auditdns --diagram --raw ".\DNS_RAW"

# Si tienes los RAW LTM para correlación:
f5auditdns diagram --raw ".\DNS_RAW" --ltm-raw-dir ".\LTM_RAW" -o ".\GSLB_Topology"

# Demo totalmente simulada, sin conectar a ningún F5:
f5auditdns diagram --mock -o ".\Demo"
```

Se crean `gtm_topology.json` (grafo y árbol de objetos) y `f5_dns_topology.html` (visor web). Basta abrir el HTML en el navegador. El HTML contiene un motor gráfico offline, y también puede utilizar **D3.js v7** cuando está disponible.

## Diagrama 100 % autónomo con D3.js v7 incluido

Para incrustar la biblioteca D3 v7 en el propio HTML, obtén `d3.v7.min.js` desde https://d3js.org/d3.v7.min.js conforme a las políticas internas y ejecuta:

```powershell
f5auditdns diagram --raw ".\DNS_RAW" --d3-js ".\d3.v7.min.js" -o ".\GSLB_Topology"
```

La herramienta no descarga JavaScript desde Internet al generar archivos. Sin `--d3-js`, el HTML abierto desde disco utiliza su motor SVG independiente; al servirlo por HTTP(S) puede intentar usar D3 desde el CDN oficial si tu política lo permite.

## Funciones disponibles

- Árbol horizontal colapsable, curvas Bézier, zoom y movimiento libre.
- Selector por partición y buscador de Wide IP, FQDN, IP, Server, Virtual Server, Data Center y monitor.
- Filtros `Todos`, `Online`, `Degradado / Offline` y `Solo auditoría / sin cadenas conocidas`.
- Panel de detalles, estado observado/derivado, evidencia LTM, estado iQuery disponible, relaciones y JSON REST **sanitizado**.
- Comandos de consulta y referencias de eliminación prefijados `NOT RUN`, sin ejecución ni aprobación automática.
- Índice global por nombre `fullPath` con referencias entre particiones (`/Common`, `/Prod_GSLB`, `/DMZ_Externo`, etc.).

El mapa sigue `BIG-IP → Partición → Wide IP → Pool → Pool Member → GSLB Virtual Server → GSLB Server → Data Center`, agregando Monitors cuando hay relaciones explícitas. Otra rama muestra objetos que no aparecen en cadenas Wide IP conocidas, sin considerarlos automáticamente eliminables.

## Cuidados importantes

- **NO VERIFIED REFERENCES IN SNAPSHOT** significa únicamente que no se encontraron referencias verificadas dentro de la captura evaluada.
- **POSSIBLE INDIRECT REFERENCES** indica que iRules, Topology o referencias dinámicas podrían usar el objeto.
- **INVENTORY INCOMPLETE** significa que faltaron datasets o consultas REST.
- Un server sin miembros conocidos todavía puede ser necesario para discovery, DR, prober o contingencia.
- Si un GSLB Virtual Server está offline, **no demuestra falla de iQuery**: solamente se usa evidencia iQuery explícita.
- `DEGRADED` es una agregación gráfica derivada de estados, no una etiqueta nativa de BIG-IP.
- La salud corresponde al momento de `collect`; no son estadísticas históricas ni tiempo real.
- No se hacen cambios a los dispositivos y **todos los comandos de eliminación son referencias NOT RUN**. Es obligatorio guardar la configuración original y obtener aprobaciones por separado.
- Los HTML/JSON incluyen información de inventario local: almacénalos internamente. Usa `--no-raw-inspector` si necesitas ocultar los JSON individuales.

## Ayuda

```powershell
f5auditdns diagram --help
f5auditdns --version
```

Para instalar el proyecto en una carpeta de desarrollo, ejecuta `py -m pip install -e ".[dev]"`. Ejecuta `py -m pytest -q` antes de subirlo a GitHub y no publiques una versión sin pruebas en la matriz Windows/Linux.

Si el RAW contiene una IP de gestión en lugar del hostname, usa `--device-label "dns01.example.test"` para definir un título visible sin modificar los datos originales.
