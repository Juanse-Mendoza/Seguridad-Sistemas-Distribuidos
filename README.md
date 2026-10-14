# Fase 4: Demostración de seguridad (vulnerable vs. protegida)

Demostración local con datos **ficticios** para el caso de la plataforma de comercio electrónico.
Compara dos APIs con la misma funcionalidad (`/login`, `/catalogo`, `/pedidos/{id}`, `/admin/usuarios`):

| Archivo | Descripción |
|---|---|
| `app_vulnerable.py` | API intencionalmente insegura (puerto 8001) |
| `app_protected.py` | API con los controles de la Fase 2 (puerto 8002) |
| `datos_demo.py` | Usuarios, pedidos y catálogo ficticios |
| `demo.py` | Arranca ambas APIs, ejecuta los escenarios y muestra la tabla comparativa |
| `analizar_logs.py` | Analiza `audit.log` y genera alertas |

> Ejecutar solo en tu propio equipo. Las APIs escuchan únicamente en `127.0.0.1`.
> `app_vulnerable.py` es inseguro a propósito: no lo expongas ni lo reutilices.

## Requisitos

- Python 3.10 o superior

## Ejecución en VS Code

1. Abre la carpeta `demo_seguridad` en VS Code (*File > Open Folder*).
2. Abre una terminal (*Terminal > New Terminal*) y crea el entorno virtual:

   ```bash
   python -m venv .venv
   ```

   Actívalo:
   - Windows (PowerShell): `.venv\Scripts\Activate.ps1`
   - Windows (cmd): `.venv\Scripts\activate.bat`
   - macOS/Linux: `source .venv/bin/activate`

   Si PowerShell bloquea el script, ejecuta una vez
   `Set-ExecutionPolicy -Scope CurrentUser RemoteSigned`.

3. Instala las dependencias:

   ```bash
   pip install -r requirements.txt
   ```

4. Ejecuta la demostración completa:

   ```bash
   python demo.py
   ```

   Cada ejecución arranca servidores nuevos, así que los contadores del límite de solicitudes
   empiezan en cero. Se genera `audit.log` con los eventos de la API protegida.

## Resultado esperado

```
Escenario                          | Configuración vulnerable               | Configuración protegida
0. Acceso legítimo (pedido propio) | HTTP 200                               | HTTP 200
1. Leer pedido de otro usuario     | HTTP 200 (datos ajenos expuestos)      | HTTP 403 (bloqueado)
2. Cliente accede a /admin         | HTTP 200 (contraseñas expuestas)       | HTTP 403 (bloqueado)
3. Token falsificado               | HTTP 200 (suplantación lograda)        | HTTP 401 (rechazado)
4. Fuerza bruta de contraseña      | contraseña descubierta en el intento 7 | bloqueado: 401x2, 429x8
5. Inundación de 50 solicitudes    | 200x50                                 | 200x26, 429x24
```

Los conteos exactos del escenario 5 pueden variar en una o dos solicitudes según cuántas
peticiones consumieron los escenarios anteriores.

## Ejecución manual (opcional, para capturas con Swagger)

En dos terminales distintas:

```bash
python -m uvicorn app_vulnerable:app --host 127.0.0.1 --port 8001
python -m uvicorn app_protected:app --host 127.0.0.1 --port 8002
```

Documentación interactiva: http://127.0.0.1:8001/docs y http://127.0.0.1:8002/docs.
Para revisar los eventos después: `python analizar_logs.py`.

## Evidencias sugeridas para el entregable

1. Captura de la tabla comparativa que imprime `demo.py`.
2. Captura del análisis de eventos y las alertas.
3. Contenido de `audit.log` (una línea JSON por evento).
4. Fragmentos de código: `usuario_actual`, `requiere_rol` y el chequeo de propietario en
   `obtener_pedido` (autenticación y autorización), `LimitadorVentana` y el middleware `proteger`
   (seguridad de API), y `auditar` (monitoreo).

## Relación con las amenazas de la Fase 1

| Amenaza | Escenario | Control en `app_protected.py` |
|---|---|---|
| A1 Acceso a cuentas ajenas | 1 y 2 | Verificación de propietario y RBAC |
| A3 DoS/DDoS | 5 | Límite de solicitudes por IP (429) |
| A4 Sin monitoreo | Análisis de logs | `audit.log` y reglas de alerta |
| A6 Suplantación | 3 y 4 | JWT firmado con expiración, hash PBKDF2, límite de login |
| A7 Inyección | Parcial | Validación de entradas con Pydantic |
| A8 Configuración y secretos | 2 | Sin contraseñas expuestas, secreto JWT desde el entorno |

## Limitaciones (insumo para la Fase 5)

- El limitador es en memoria y de un solo proceso. En producción debe vivir en el gateway o en un almacén compartido como Redis.
- Se usa HTTP local. En producción todo el tráfico debe ir por TLS, y entre servicios por mTLS.
- No hay base de datos real, MFA ni gestión de secretos con rotación.
- El log es un archivo local sin protección contra alteración. En producción se envía a un SIEM.
- Los servicios del diagrama (catálogo, pagos, inventario) no están separados en procesos: la demo cubre la capa de API.
- La demo cubre A1, A3, A4 y A6. Las amenazas A2 (TLS) y A5 (permisos entre servicios) se resuelven a nivel de arquitectura y se documentan en el diagrama.
