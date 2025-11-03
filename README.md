# Autoscan

Autoscan es una reimplementacion en Python del flujo original `nmap_auto-masivo.sh`.
Incluye persistencia en SQLite, reanudacion de tareas, exportaciones y manejo
organizado de reportes `-oA`.

## Requisitos

- Python 3.10 o superior.
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

# Ejecutar dentro de Pipenv sin activar shell
pipenv run python -m autoscan scan -H 192.168.1.10 --vul high --report
```

Opciones principales:

- `-H/--host`: Hostname o IP (opcional si se usa `-lh`).
- `-lh/--list-hosts`: Archivo con una lista de hosts/IP.
- `--vul [high|medium|low]`: Activa scripts `vulners` con umbral CVSS (por defecto `high`).
- `--slow` / `--fast`: Ajustan el perfil de velocidad (`-T2` / `-T5`).
- `-w/--workers`: Numero de hosts concurrentes.
- `--report [ruta]`: Genera jerarquia de reportes `-oA`. Si no se indica ruta, se usa el nombre del host o del archivo de lista.
- `--db-path`: Ruta a la base SQLite (por defecto `./autoscan.db`).
- `--no-ping`: Omite la fase de descubrimiento y fuerza `-Pn`.
- `--force`: Repite el escaneo aunque el host ya figure como terminado.

Al presionar `Ctrl+C` el programa pregunta si debe detener el escaneo; al confirmar, finaliza los trabajos en curso y marca el resto como pendientes.

Cada host completado muestra un resumen con sistema operativo estimado y los servicios detectados junto a sus versiones. Si se detecta el patron de puertos 21, 554 y 1723 (con o sin el 53 adicional) simultaneamente, se asume la presencia de un firewall y esos puertos se omiten de la fase detallada (quedando reflejado en el log).

## Exportacion de resultados

```bash
python3 -m autoscan export --format csv --output resultados.csv
```

Formatos soportados: `csv`, `json`, `xlsx`.

## Esquema de datos

La base SQLite incluye:

- `hosts`: estado general, sistema operativo detectado, bandera `done`.
- `ports`: puertos abiertos, servicios y banners.
- `vulnerabilities`: hallazgos de `vulners` y `vulscan` vinculados a cada puerto.

Con esta informacion es posible reanudar escaneos sin reprocesar los hosts ya completados.
