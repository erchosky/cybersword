# Changelog

## 1.1.0 - 2026-09-29

### Seguridad y uso responsable

- **El análisis de una IP ya no escanea sus puertos por defecto.** Antes, cualquier consulta (incluida la de una IP sospechosa de un email) conectaba con sus puertos sin preguntar. Ahora es pasivo; el escaneo requiere confirmación en el menú o `--scan-ports` en la línea de comandos.
- **El escáner web pide confirmación de autorización** antes de las opciones que lanzan cientos de peticiones.
- Las contraseñas de cifrado y descifrado se piden sin eco en pantalla.
- Los logs de investigación no se guardan salvo que se active `output.save_logs` (antes se guardaban si la configuración no incluía la sección `output`).
- NumVerify: la consulta iba por HTTP sin cifrar y sin clave (siempre fallaba y enviaba el teléfono en claro). Ahora solo se hace con clave y por HTTPS.

### Corregido

- URLhaus y MalwareBazaar fallaban siempre: abuse.ch exige una clave (`Auth-Key`) desde 2025. Nueva variable `CYBERSWORD_ABUSECH_API_KEY`.
- El análisis de URLs estudiaba el dominio original: con enlaces acortados se analizaba bit.ly en vez del destino real. Ahora WHOIS, DNS, certificado, reputación y typosquatting usan el destino final.
- Una URL presente en URLhaus no sumaba riesgo (solo se contemplaba el estado `is_host`).
- Falsos positivos por coincidencias parciales: `microsoft.com` se detectaba como acortador (contiene `t.co`); en emails y SMS, "ing" coincidía con "shipping", "ups" con "groups", "chase" con "purchase", "pin" con "shipping"… Ahora se compara por palabra completa y por dominio exacto.
- Escáner web: webs que devuelven 200 o redirigen a /login para cualquier ruta hacían aparecer todos los archivos sensibles como expuestos. Nueva referencia de "soft 404" compartida por el fuzzing y la búsqueda de archivos.
- `fuzz_directories` ignoraba la lista de rutas personalizada.
- `Ctrl+C` cerraba el programa entero en lugar de cancelar el análisis y volver al menú.
- El escaneo de puertos no funcionaba con IPv6; OTX recibía IPv6 como IPv4.
- `Received-SPF: Pass` no se reconocía como SPF válido.
- Typosquatting: se comparaban solo la primera etiqueta y con un umbral que marcaba `dhs.gov` como DHL; ahora se analizan todas las etiquetas, las partes con guiones y la marca exacta entre guiones (`paypal-secure-login.com`).
- El certificado TLS mostraba la versión del protocolo vacía; eliminado `datetime.utcnow()` (obsoleto).
- Un timeout explícito en `safe_get` era ignorado por el de la configuración; una variable de entorno vacía anulaba la clave de `config.yaml`.
- Límite de peticiones (429): ya no bloquea 60 segundos; devuelve un aviso.
- El analizador de archivos leía el archivo entero en memoria cuatro veces y aceptaba carpetas; ahora lee una vez, con un máximo de 50 MB para el análisis de contenido.
- Enlaces de búsqueda de teléfonos sin codificar; generador de contraseñas sin longitud mínima.

### Cambiado

- Python 3.14 recomendado (mínimo 3.12); dependencias actualizadas y `pylock.toml` regenerado. `pip-audit` sin vulnerabilidades.
- Eliminada la clave `whoisxml`, que no se usaba.
- Tests: de 11 a 60, organizados por área y sin acceso a la red.
- README en español, CI con GitHub Actions (Python 3.12 y 3.14) e informe histórico movido a `docs/`.

## 1.0.0 - 2026-07-22

Versión archivada original. Ver [docs/ARCHIVE_REPORT.md](docs/ARCHIVE_REPORT.md).
