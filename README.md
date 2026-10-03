# CyberSword

Mi navaja suiza para mirar emails, enlaces, archivos y otras cosas que huelen raro antes de fiarme. CyberSword funciona desde la terminal y junta herramientas de ciberseguridad **defensiva** en un mismo sitio.

Para ese mensaje de «entra aquí urgentemente» que ya viene dando mal rollo, sabeehh. Puedes revisar:

- **Emails** (`.eml` o cabeceras pegadas): SPF, DKIM y DMARC, saltos entre servidores, Reply-To falsos, enlaces, adjuntos y puntuación de phishing.
- **URLs y dominios**: sigue redirecciones y acortadores hasta el destino real; analiza WHOIS, DNS, certificado TLS, reputación (VirusTotal, Google Safe Browsing, URLhaus, PhishTank) y dominios que imitan marcas (`paypa1.com`, `paypal-secure-login.com`).
- **SMS y mensajes**: detecta smishing por urgencia, marcas suplantadas y enlaces acortados.
- **IPs**: geolocalización, reputación (AbuseIPDB, VirusTotal, OTX…) y, solo si lo pides, escaneo de puertos.
- **Teléfonos**: operador, tipo de línea y reputación.
- **Archivos**: hashes, tipo real, cabeceras PE, cadenas, indicadores de compromiso y consulta en VirusTotal y MalwareBazaar.
- **Inteligencia de amenazas**: consulta un indicador (IP, dominio, URL, hash o email) en varias fuentes a la vez.
- **OSINT**: filtraciones de un email (HaveIBeenPwned), presencia de un nombre de usuario y metadatos EXIF.
- **Criptografía**: hashes, cifrado AES-256 autenticado, codificaciones y fortaleza de contraseñas.
- **Escáner web**: cabeceras de seguridad, CMS, archivos sensibles expuestos y rutas.
- **Informes** en HTML, JSON o texto.

## Uso responsable

Úsalo solo con sistemas, archivos y objetivos **propios o para los que tengas autorización expresa**.

- Por defecto todo es **pasivo**: consulta servicios de reputación y registros públicos.
- Las dos funciones **activas** (escaneo de puertos y escáner web) piden confirmación de autorización antes de ejecutarse. En la línea de comandos, el escaneo de puertos exige además la opción `--scan-ports`. Escanear sistemas ajenos puede estar prohibido por ley o por tu proveedor.
- Las investigaciones pueden contener datos personales. **No se guardan logs** salvo que actives `output.save_logs`; `logs/`, `reports/`, `config.yaml` y `.env*` están excluidos de Git.

## Cómo arrancarlo

### 1. Requisitos

- **Python 3.12 o superior** (recomendado 3.14; el archivo `.python-version` lo indica para pyenv/uv).
- Conexión a Internet para las consultas de reputación, WHOIS y DNS.
- Opcional en macOS, para detectar mejor el tipo de archivo: `brew install libmagic`.

### 2. Descargar y crear el entorno virtual

```bash
git clone https://github.com/erchosky/cybersword.git cybersword
cd cybersword
python3 -m venv .venv
source .venv/bin/activate          # En Windows: .venv\Scripts\activate
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
```

`pylock.toml` fija el entorno exacto verificado (macOS con Apple Silicon y Python 3.14). En esa plataforma puedes usarlo en lugar de `requirements.txt`:

```bash
python -m pip install -r pylock.toml
```

Para la detección mejorada de tipos de archivo (necesita `libmagic`):

```bash
python -m pip install -r requirements-optional.txt
```

### 3. Configurar las claves de API (opcional)

Todo funciona sin claves, pero las consultas de reputación necesitan las suyas; la mayoría tienen un plan gratuito. Dos formas de configurarlas:

**Asistente** (guarda `config.yaml` con permisos solo para tu usuario):

```bash
python cybersword.py --setup
```

**Variables de entorno** (los nombres están en `.env.example`; el proyecto no carga `.env` automáticamente):

```bash
export CYBERSWORD_VIRUSTOTAL_API_KEY="..."
```

| Variable | Para qué sirve | Dónde conseguirla |
|---|---|---|
| `CYBERSWORD_VIRUSTOTAL_API_KEY` | Reputación de URLs, IPs, dominios y archivos | virustotal.com |
| `CYBERSWORD_ABUSECH_API_KEY` | URLhaus y MalwareBazaar (obligatoria desde 2025) | auth.abuse.ch |
| `CYBERSWORD_ABUSEIPDB_API_KEY` | Reputación de IPs | abuseipdb.com |
| `CYBERSWORD_SHODAN_API_KEY` | Servicios expuestos y CVE conocidos de una IP | shodan.io |
| `CYBERSWORD_IPINFO_API_KEY` | Geolocalización con más cuota (funciona sin clave) | ipinfo.io |
| `CYBERSWORD_HAVEIBEENPWNED_API_KEY` | Filtraciones de un email | haveibeenpwned.com |
| `CYBERSWORD_GOOGLE_SAFE_BROWSING_API_KEY` | Listas de Google de phishing y malware | Google Cloud |
| `CYBERSWORD_ALIENVAULT_OTX_API_KEY` | Inteligencia de amenazas OTX | otx.alienvault.com |
| `CYBERSWORD_IPQUALITYSCORE_API_KEY` | Fraude en IPs, emails y teléfonos | ipqualityscore.com |
| `CYBERSWORD_NUMVERIFY_API_KEY` | Validación de teléfonos (solo por HTTPS) | numverify.com |

Nunca subas `config.yaml` a un repositorio.

### 4. Usarlo

Menú interactivo:

```bash
python cybersword.py
```

Línea de comandos:

```bash
python cybersword.py --url https://bit.ly/ejemplo
python cybersword.py --sms "URGENTE: verifica tu cuenta en https://example.com"
python cybersword.py --ip 1.1.1.1                    # pasivo
python cybersword.py --ip 192.0.2.10 --scan-ports    # activo: solo con autorización
python cybersword.py --email persona@example.com
python cybersword.py --file ./adjunto.pdf
python cybersword.py --phone +34600123456
python cybersword.py --ioc d41d8cd98f00b204e9800998ecf8427e
python cybersword.py --username usuario_ejemplo
```

- `--quiet` imprime solo JSON (útil con `jq`): `python cybersword.py --quiet --sms "texto" | jq .risk_score`
- `--output html|json|txt|all` guarda el informe en `reports/`.
- `Ctrl+C` cancela el análisis en curso y vuelve al menú.

## Estructura

```text
cybersword.py          Punto de entrada: opciones, asistente de configuración y menú
modules/               Un módulo por herramienta (email, url, ip, phone, sms, osint,
                       crypto, file, web_scanner, threat_intel, reporter)
utils/helpers.py       Configuración, caché, límites de peticiones, validadores y logs
utils/api_manager.py   Adaptadores de las APIs externas
utils/output.py        Salida en terminal, confirmaciones y exportación de informes
wordlists/             Rutas para el escáner web
tests/                 Tests (sin red: los servicios externos se simulan)
docs/                  Informe histórico del archivado
```

## Desarrollo

```bash
python -m pip install -r requirements-dev.txt
ruff check .
pytest -q
bandit -q -r cybersword.py modules utils -lll
pip-audit -r requirements.txt
```

La CI de GitHub Actions ejecuta estas comprobaciones con Python 3.12 y 3.14.

## Hasta dónde puedes fiarte del resultado

- Los resultados de reputación dependen de servicios externos, de sus cuotas y de tus claves.
- Los límites de peticiones son locales y aproximados; manda el proveedor.
- La entropía de una contraseña es una estimación.
- Los gráficos del panel HTML se cargan desde una CDN; sin conexión el informe se ve, pero sin gráficos.
- El análisis de contenido de un archivo se limita a sus primeros 50 MB (los hashes usan el archivo completo).

## Historial

Cambios en [CHANGELOG.md](CHANGELOG.md). Informe del archivado original en [docs/ARCHIVE_REPORT.md](docs/ARCHIVE_REPORT.md).
