# Publicación de F5AuditDNS desde GitHub Actions

Esta configuración añade publicación automática sin tokens permanentes mediante **Trusted Publishing (OIDC)**.
No modifica el código ni la versión del proyecto (0.1.2).

## Archivos

- `.github/workflows/ci.yml`: pruebas en cada push / pull request.
- `.github/workflows/publish-testpypi.yml`: publicación manual a TestPyPI.
- `.github/workflows/release.yml`: publicación a PyPI después de publicar un GitHub Release **no prerelease**.

## 1. Subir el proyecto

Descomprime el ZIP y sube el **contenido** de la carpeta a un repositorio GitHub. No publiques sólo el ZIP.

## 2. Crear entornos (GitHub)

Repository → Settings → Environments → New environment:

- `testpypi`
- `pypi` (recomendado: configurar Required reviewers y restricciones a tags `v*` para la publicación final).

Algunos ajustes de protección dependen de las características de GitHub disponibles para el repositorio/plan.

## 3. Registrar Trusted Publishers

Si el proyecto aún no existe en TestPyPI, abre https://test.pypi.org/manage/account/publishing/ y configura un *pending publisher*. Si ya existe, entra a su apartado **Publishing**.

- Project name: `f5auditdns` (debe coincidir con `pyproject.toml`)
- GitHub owner: el nombre **real** de tu usuario u organización
- Repository: nombre **real** del repo (por ejemplo `F5AuditDNS`)
- Workflow: `publish-testpypi.yml`
- Environment: `testpypi`

En https://pypi.org/manage/account/publishing/ registra la publicación final con:

- Project name: `f5auditdns`
- GitHub owner: tu usuario u organización
- Repository: tu repo
- Workflow: `release.yml`
- Environment: `pypi`

Los nombres deben coincidir exactamente con GitHub. PyPI y TestPyPI tienen cuentas y configuración independientes. El nombre del paquete debe estar disponible; un pending publisher no reserva un nombre.

## 4. Publicar en TestPyPI

GitHub → Actions → **Publish F5AuditDNS to TestPyPI** → **Run workflow**.

Se ejecutan pruebas, se construyen `sdist` y `wheel`, se revisan metadatos y se sube a TestPyPI, si existe autorización.

**Atención:** no puedes volver a subir el mismo nombre+versión a un índice si ya existe. Incrementa la versión en `pyproject.toml` y `f5auditdns/__init__.py` si corresponde antes del siguiente intento de publicación.

## 5. Publicar en PyPI

GitHub → Releases → Draft a new release → Tag: `v0.1.2` → Publish release.

El workflow comprueba que el tag sea exactamente `v` más la versión de `pyproject.toml`, ejecuta pruebas, construye distribuciones y, después de aprobar el entorno si corresponde, publica a PyPI.

Las Releases marcadas **pre-release** no se suben a PyPI mediante este workflow.

## 6. Instalar el paquete

Desde PyPI, una vez publicado:

```powershell
py -m pip install f5auditdns
f5auditdns --version
```

Desde TestPyPI (para probar la distribución, con dependencias obtenidas de PyPI):

```powershell
py -m pip install --index-url https://test.pypi.org/simple/ --extra-index-url https://pypi.org/simple/ f5auditdns==0.1.2
```

**Nota:** combinar índices puede introducir riesgos de dependencia con nombres duplicados; usa un entorno aislado y revisa las dependencias. También puedes descargar el wheel desde TestPyPI e instalarlo por ruta con dependencias verificadas.

## 7. Precauciones

- Verifica la propiedad del repo antes de dar permisos OIDC en PyPI.
- Mantén el entorno `pypi` con revisión manual.
- No publiques snapshots JSON de equipos ni credenciales en GitHub.
- Un paquete en PyPI no puede tener dos distribuciones diferentes con el mismo nombre y versión.
- Prueba F5AuditDNS con un BIG-IP DNS real antes de anunciarlo como listo para producción.

Referencias: https://docs.pypi.org/trusted-publishers/using-a-publisher/ y https://packaging.python.org/en/latest/guides/publishing-package-distribution-releases-using-github-actions-ci-cd-workflows/
