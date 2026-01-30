# Autoscan

Autoscan es una reimplementacion en Python del flujo original `nmap_auto-masivo.sh`.
Incluye persistencia en SQLite, reanudacion de tareas, exportaciones y manejo
organizado de reportes `-oA`.

## Requisitos

- Python 3.10 o superior (para usar archivos TOML se recomienda 3.11+).
- Nmap disponible en el `PATH`.

## Instalacion rapida

- Copia o clona el proyecto, por ejemplo en `~/scripts/autoscan`.
- (Opcional) Crea un entorno virtual clasico:
  - `python3 -m venv .venv`
  - `source .venv/bin/activate`
- (Alternativa) Usa Pipenv: `pipenv install && pipenv shell`.
- Desde la raiz del proyecto valida la instalacion con `python3 -m autoscan --help`.

## Uso rapido

```bash
# Interprete estandar o venv activado
python3 -m autoscan scan -H 192.168.1.10 --vul high --report

# Nuevo flujo discovery (tcp/udp/full)
python3 autoscan.py scan discovery tcp vul
python3 autoscan.py scan discovery tcp vul high
python3 autoscan.py scan discovery udp
python3 autoscan.py scan discovery full vul medium

# Ejecutar dentro de Pipenv sin activar shell
pipenv run python -m autoscan scan -H 192.168.1.10 --vul high --report
```

Opciones principales:

- `-H/--host`: Hostname o IP (opcional si se usa `-lh`).
- `-lh/--list-hosts`: Archivo con una lista de hosts/IP (las entradas duplicadas se eliminan automáticamente). Si no se especifica, se busca `hosts.txt` en el directorio actual.
- `scan discovery tcp|udp|full [vul]`: nuevo flujo de descubrimiento con lectura automática de `hosts.txt` y activación opcional de vulners con `vul`.
- `--vul [high|medium|low]`: Activa scripts `vulners` con umbral CVSS (por defecto `high`). Los scripts `default` y `vuln` se ejecutan con la exclusión de la categoría `dos` para evitar chequeos potencialmente disruptivos.
- `--slow` / `--fast`: Ajustan el perfil de velocidad (`-T2` / `-T5`).
- `-w/--workers`: Numero de hosts concurrentes.
- `--report [ruta]`: Genera jerarquia de reportes `-oA`. Si no se indica ruta, se usa el nombre del host o del archivo de lista.
- `--db-path`: Ruta a la base SQLite (por defecto `./autoscan.db`).
- `--no-ping`: Omite la fase de descubrimiento y fuerza `-Pn`.
- `--force`: Repite el escaneo aunque el host ya figure como terminado.
- `--scan-config`: Ruta a `scan.toml` (si no se indica, se busca `scan.toml` en el directorio actual).
- `--log-level`: Nivel de log (si no se define, se usa el del TOML).

Al presionar `Ctrl+C` el programa pregunta si debe detener el escaneo; al confirmar, finaliza los trabajos en curso y marca el resto como pendientes.

Cada host completado muestra un resumen con sistema operativo estimado y los servicios detectados junto a sus versiones. Si se detecta el patron de puertos 21, 554 y 1723 (con o sin el 53 adicional) simultaneamente, se asume la presencia de un firewall y esos puertos se omiten de la fase detallada. Cuando se observan patrones anómalos (los puertos 1-20 abiertos en bloque o más de 1.000 puertos reportados como abiertos) se considera un falso positivo y la fase profunda se limita a `--top-ports 50`; todos estos casos quedan reflejados en el log.

El motor imprime un banner con la version en cada ejecucion (si existe `src/banner.ans` y la salida es TTY), y guarda un log persistente en `run.log` (configurable via TOML).

## Configuracion TOML

Si existe `scan.toml` en el directorio actual (o se pasa con `--scan-config`), se usa como fuente de defaults. CLI siempre tiene prioridad.

Ejemplo `scan.toml`:

```toml
[scan]
workers = 4
resume = true
use_ping = true
report_dir = "reports"
log_file = "run.log"
scan_type = "tcp" # tcp | udp | full
log_level = "info"
vul_level = "high"

[scan.speed]
timing_template = 3
min_rate = 1000
max_retries = 4
```

## Exportacion de resultados

Export principal (nuevo flujo):

```bash
python3 autoscan.py db export --format xlsx --output resultados.xlsx
python3 autoscan.py db export --mode min --format xlsx --output resultados_min.xlsx
python3 autoscan.py db export --host 10.0.0.1 --format csv --output host_10.csv
python3 autoscan.py db export --host 10.0.0.1,10.0.0.2 --format json --output hosts.json
```

Modos soportados:

- `full`: todas las columnas.
- `min`: `host, os_vendor, port, protocol, product, banner`.

Formatos soportados: `csv`, `json`, `xlsx`.

Opciones adicionales:

- `--db-config`: Ruta a `db.toml` (si no se indica, se busca `db.toml` en el directorio actual).
- `--db-path`: Ruta a la base (puede venir de TOML).

Export legacy (compatibilidad):

```bash
python3 -m autoscan export --format xlsx --output resultados.xlsx --no-vul
```

En legacy, `--no-vul` excluye columnas de vulnerabilidades pero conserva el resto.

Ejemplo `db.toml`:

```toml
[db]
db_path = "autoscan.db"
no_vul = false
export_mode = "full"
log_file = "run.log"
```

## Esquema de datos

La base SQLite incluye:

- `hosts`: estado general, sistema operativo detectado, bandera `done`.
- `ports`: puertos abiertos, servicios y banners.
- `vulnerabilities`: hallazgos de `vulners` y `vulscan` vinculados a cada puerto.

Con esta informacion es posible reanudar escaneos sin reprocesar los hosts ya completados.
