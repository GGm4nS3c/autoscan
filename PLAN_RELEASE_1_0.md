# Autoscan - Propuesta Mejorada y Plan de Trabajo (Release 1.0)

Este documento resume y mejora la propuesta de trabajo para definir la estrategia
del motor de descubrimiento y escaneo. No implica cambios en codigo; es solo para
alinear criterios y el roadmap.

---

## Vision del producto

Autoscan sera el motor de descubrimiento de hosts y escaneo de servicios.
Su salida se almacenara en SQLite para consumo posterior por APIs y otros
aplicativos (visualizacion en front en releases futuros).

---

## Alcance Release 1.0

**Objetivo principal:** motor de descubrimiento estable + persistencia en DB.

Incluye:
- Modulo `scan` (descubrimiento y servicios).
- Modulo `db` (export, insert, update, delete).
- Configuracion via archivos TOML.
- Logs en consola y archivo `run.log`.
- Banner con version del motor de descubrimiento.

No incluye:
- Frontend.
- API de consulta.
- Analitica avanzada o correlacion externa.

---

## Configuracion TOML

Separar configuraciones por modulo:

### 1) `scan.toml`
Debe contener:
- Perfil de velocidad (`T`, `min-rate`, `max-retries`).
- Puertos por defecto (si aplica a top-ports o listas fijas).
- Ruta base de output (ej: `hosts/{ip}/...`).
- Flags globales (reanudacion, reportes, OS detection, uso de scripts).
- Concurrencia (workers).
- Parametros por tipo de scan (tcp/udp/full, con o sin vul).

### 2) `db.toml`
Debe contener:
- Ruta por defecto de la base de datos.
- Modo de export por defecto (full/min).
- Parametros de validacion de entradas (insert/update).

---

## CLI propuesta

### `autoscan.py scan`
Subcomandos propuestos:
- `autoscan.py scan discovery tcp`
- `autoscan.py scan discovery udp`
- `autoscan.py scan discovery full`

Flujo general:
1) Descubrimiento de puertos:
   - TCP: `nmap -p- -n -oA hosts/{ip}/initial -T3 --min-rate 1000 --max-retries 4 -sT/-sS {ip}`
   - UDP: `nmap -sU -n -oA hosts/{ip}/initial -T3 --min-rate 1000 --max-retries 4 {ip}`
2) Extraccion de puertos abiertos.
3) Escaneo de servicios:
   - `nmap -sUV -O -n -oA hosts/{ip}/service -T3 --min-rate 1000 --max-retries 4 -Pn -p {puertos}`

Modo con vulners:
- Scripts: `--script=default and not dos,vuln and not dos,vulners`
- Args: `--script-args=vulners.mincvss=8.0`

### Reanudacion (flag booleano)
- Si `resume=true`, no repetir hosts ya marcados como `done`.
- Si `resume=false`, forzar reescaneo y sobrescribir.
- La BD mantiene `done` por host.
- Si el host no existe, se inserta.

---

## Modulo DB

### `autoscan.py db export`
Parametros:
- `--host` (single o lista).
- `--mode` (`full` o `min`).
- `--format` (`xlsx`, `csv`, `json`).

**Modo `min`:** columnas solo `host, os_vendor, port, protocol, product, banner`.

### `autoscan.py db delete`
- `--host` (ip/host/cidr) o `--all`.
- Confirmacion obligatoria (y/n).

### `autoscan.py db insert`
- `--file` (`xlsx`, `json`, `csv`).
- Validar encabezados y formato esperado.

### `autoscan.py db update`
- `--file` (`xlsx`, `json`, `csv`).
- Validar encabezados y formato esperado.

---

## Logging

Requisitos:
- Log en consola (colores).
- Log persistente en `run.log`.
- Nivel configurable (info/debug).
- Mensaje de advertencia cuando no haya conectividad a Vulners.

---

## Versionado y banner

Debe mostrarse al iniciar:
- Nombre del motor.
- Version semantica (ej: `1.0.0`).
- Fecha de build o commit short hash (opcional).

---

## Riesgos y mitigaciones

Riesgo:
- Falsos positivos (firewalls devolviendo puertos abiertos).
Mitigacion:
- Heuristicas y fallback a top-ports.

Riesgo:
- Bloqueo de API Vulners (Cloudflare).
Mitigacion:
- Advertir y continuar sin detener flujo.

---

## Preguntas abiertas

1) Formato final de `scan.toml` y `db.toml` (nombres exactos de keys).
2) Definir top-ports default (50, 100, 200).
3) Definir limites de workers segun recursos.
4) Definir estrategia para UDP (tiempos y retries).

---

## Proximo paso sugerido

1) Definir el esquema exacto de `scan.toml` y `db.toml`.
2) Alinear CLI final y sus opciones.
3) Implementar versionado y banner.
4) Agregar logging en archivo `run.log`.

