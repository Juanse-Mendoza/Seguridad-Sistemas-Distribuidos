"""API PROTEGIDA: misma funcionalidad que app_vulnerable.py, con controles de seguridad.

Controles implementados (Fase 2):
  Autenticación       Hash PBKDF2 con sal + token JWT firmado con expiración (15 min).
  Autorización        RBAC y verificación de propiedad del recurso (objeto).
  Seguridad de API    Límite de solicitudes por IP, validación de entradas y cabeceras seguras.
  Monitoreo/auditoría Eventos de seguridad en formato JSON (audit.log).

Limitaciones de esta demo (se discuten en la Fase 5):
  - El limitador es en memoria y de un solo proceso (en producción: gateway/Redis).
  - Se usa HTTP local; en producción todo el tráfico debe ir por TLS.
  - Los datos viven en memoria (sin base de datos real).
"""

import hashlib
import hmac
import json
import os
import secrets
import time
import uuid
from collections import defaultdict, deque
from datetime import datetime, timedelta, timezone

import jwt
from fastapi import Depends, FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field

from datos_demo import CATALOGO, PEDIDOS, USUARIOS_DEMO

# ---------------------------------------------------------------- Configuración
# El secreto se toma del entorno; si no existe se genera aleatorio al arrancar.
JWT_SECRET = os.environ.get("JWT_SECRET") or secrets.token_urlsafe(32)
JWT_ALG = "HS256"
JWT_MINUTOS = 15
LOG_FILE = os.environ.get("AUDIT_LOG", "audit.log")

LIMITE_LOGIN = (5, 60)  # 5 intentos de login por minuto y por IP
LIMITE_API = (30, 60)  # 30 solicitudes por minuto y por IP

app = FastAPI(title="API protegida (demo)")


# ---------------------------------------------------------- Contraseñas con hash
def calcular_hash(password: str, sal: bytes) -> str:
    return hashlib.pbkdf2_hmac("sha256", password.encode(), sal, 200_000).hex()


USUARIOS = {}
for _nombre, _datos in USUARIOS_DEMO.items():
    _sal = os.urandom(16)
    USUARIOS[_nombre] = {
        "sal": _sal,
        "hash": calcular_hash(_datos["password"], _sal),
        "rol": _datos["rol"],
    }

# Para igualar tiempos de respuesta cuando el usuario no existe.
_SAL_FALSA = os.urandom(16)
_HASH_FALSO = calcular_hash("no-existe", _SAL_FALSA)


# ------------------------------------------------------------------- Auditoría
def auditar(evento: str, request: Request, usuario: str | None = None, detalle: str = "") -> None:
    """Escribe un evento de seguridad (nunca contraseñas ni tokens)."""
    registro = {
        "ts": datetime.now(timezone.utc).isoformat(),
        "evento": evento,
        "usuario": usuario,
        "ip": request.client.host if request.client else "?",
        "ruta": request.url.path,
        "detalle": detalle,
    }
    with open(LOG_FILE, "a", encoding="utf-8") as archivo:
        archivo.write(json.dumps(registro, ensure_ascii=False) + "\n")


# ----------------------------------------------------------- Límite de solicitudes
class LimitadorVentana:
    """Ventana deslizante en memoria: máximo N solicitudes por ventana y por clave."""

    def __init__(self, maximo: int, ventana_seg: int):
        self.maximo = maximo
        self.ventana = ventana_seg
        self.registros: dict[str, deque] = defaultdict(deque)

    def permitir(self, clave: str) -> tuple[bool, int]:
        ahora = time.monotonic()
        cola = self.registros[clave]
        while cola and ahora - cola[0] > self.ventana:
            cola.popleft()
        if len(cola) >= self.maximo:
            return False, int(self.ventana - (ahora - cola[0])) + 1
        cola.append(ahora)
        return True, 0


limitador_login = LimitadorVentana(*LIMITE_LOGIN)
limitador_api = LimitadorVentana(*LIMITE_API)


@app.middleware("http")
async def proteger(request: Request, call_next):
    ip = request.client.host if request.client else "desconocida"
    es_login = request.url.path == "/login"
    limitador = limitador_login if es_login else limitador_api
    permitido, espera = limitador.permitir(ip)
    if not permitido:
        auditar("RATE_LIMIT_EXCEDIDO", request, detalle="login" if es_login else "api")
        return JSONResponse(
            {"detalle": "Demasiadas solicitudes. Intente más tarde."},
            status_code=429,
            headers={"Retry-After": str(espera)},
        )
    respuesta = await call_next(request)
    respuesta.headers["X-Content-Type-Options"] = "nosniff"
    respuesta.headers["X-Frame-Options"] = "DENY"
    respuesta.headers["Cache-Control"] = "no-store"
    return respuesta


# ------------------------------------------------------------ Autenticación (JWT)
class Credenciales(BaseModel):
    # Validación de entradas: longitud y caracteres permitidos.
    username: str = Field(min_length=1, max_length=32, pattern=r"^[a-zA-Z0-9_.-]+$")
    password: str = Field(min_length=1, max_length=64)


def usuario_actual(request: Request) -> dict:
    cabecera = request.headers.get("Authorization", "")
    if not cabecera.startswith("Bearer "):
        auditar("TOKEN_AUSENTE", request)
        raise HTTPException(401, "Autenticación requerida", headers={"WWW-Authenticate": "Bearer"})
    token = cabecera[7:]
    try:
        datos = jwt.decode(
            token, JWT_SECRET, algorithms=[JWT_ALG], options={"require": ["exp", "sub"]}
        )
    except jwt.ExpiredSignatureError:
        auditar("TOKEN_EXPIRADO", request)
        raise HTTPException(401, "Token expirado", headers={"WWW-Authenticate": "Bearer"})
    except jwt.InvalidTokenError:
        auditar("TOKEN_INVALIDO", request)
        raise HTTPException(401, "Token inválido", headers={"WWW-Authenticate": "Bearer"})
    return {"usuario": datos["sub"], "rol": datos.get("rol", "cliente")}


# ------------------------------------------------------------ Autorización (RBAC)
def requiere_rol(*roles_permitidos: str):
    def verificar(request: Request, actual: dict = Depends(usuario_actual)) -> dict:
        if actual["rol"] not in roles_permitidos:
            auditar(
                "ACCESO_DENEGADO_ROL",
                request,
                usuario=actual["usuario"],
                detalle=f"rol={actual['rol']}",
            )
            raise HTTPException(403, "No tiene permisos para este recurso")
        return actual

    return verificar


# ------------------------------------------------------------------- Endpoints
@app.post("/login")
def login(datos: Credenciales, request: Request):
    usuario = USUARIOS.get(datos.username)
    sal = usuario["sal"] if usuario else _SAL_FALSA
    esperado = usuario["hash"] if usuario else _HASH_FALSO
    calculado = calcular_hash(datos.password, sal)
    if not (usuario and hmac.compare_digest(calculado, esperado)):
        auditar("LOGIN_FALLIDO", request, usuario=datos.username)
        raise HTTPException(401, "Credenciales inválidas")

    ahora = datetime.now(timezone.utc)
    token = jwt.encode(
        {
            "sub": datos.username,
            "rol": usuario["rol"],
            "iat": ahora,
            "exp": ahora + timedelta(minutes=JWT_MINUTOS),
            "jti": uuid.uuid4().hex,
        },
        JWT_SECRET,
        algorithm=JWT_ALG,
    )
    auditar("LOGIN_EXITOSO", request, usuario=datos.username)
    return {"token": token, "tipo": "Bearer", "expira_en_min": JWT_MINUTOS}


@app.get("/catalogo")
def catalogo():
    return CATALOGO


@app.get("/pedidos/{pedido_id}")
def obtener_pedido(pedido_id: int, request: Request, actual: dict = Depends(usuario_actual)):
    pedido = PEDIDOS.get(pedido_id)
    if not pedido:
        raise HTTPException(404, "Pedido no encontrado")
    # Autorización a nivel de objeto: solo el dueño o un rol operativo.
    if pedido["dueno"] != actual["usuario"] and actual["rol"] not in ("admin", "operador_pedidos"):
        auditar(
            "ACCESO_DENEGADO_OBJETO",
            request,
            usuario=actual["usuario"],
            detalle=f"pedido={pedido_id}",
        )
        raise HTTPException(403, "No tiene permisos para este pedido")
    return pedido


@app.get("/admin/usuarios")
def listar_usuarios(actual: dict = Depends(requiere_rol("admin"))):
    # Nunca se devuelven contraseñas ni hashes.
    return [{"usuario": nombre, "rol": datos["rol"]} for nombre, datos in USUARIOS.items()]
