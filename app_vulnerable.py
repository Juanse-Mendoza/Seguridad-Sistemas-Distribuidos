"""API INTENCIONALMENTE VULNERABLE (solo para la demostración académica).

Ejecutar únicamente en 127.0.0.1. No exponer a Internet ni reutilizar este código.

Fallos que ilustra (relacionados con las amenazas de la Fase 1):
  A1  Sin autorización a nivel de objeto (cualquier usuario lee pedidos ajenos).
  A1  Sin control de roles (cualquier usuario autenticado usa /admin).
  A3  Sin límite de solicitudes (permite fuerza bruta e inundación).
  A4  Sin registro de eventos de seguridad.
  A6  Token predecible (es el nombre de usuario): se puede falsificar.
  A8  Contraseñas guardadas y expuestas en texto plano.
"""

from fastapi import FastAPI, HTTPException, Request
from pydantic import BaseModel

from datos_demo import CATALOGO, PEDIDOS, USUARIOS_DEMO

app = FastAPI(title="API vulnerable (demo)")


class Credenciales(BaseModel):
    username: str
    password: str


def usuario_desde_token(request: Request) -> str:
    cabecera = request.headers.get("Authorization", "")
    if not cabecera.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Falta token")
    # FALLO: el "token" es simplemente el nombre de usuario, sin firma ni expiración.
    usuario = cabecera[7:]
    if usuario not in USUARIOS_DEMO:
        raise HTTPException(status_code=401, detail="Token inválido")
    return usuario


@app.post("/login")
def login(datos: Credenciales):
    usuario = USUARIOS_DEMO.get(datos.username)
    # FALLO: comparación en texto plano, sin límite de intentos ni registro.
    if not usuario or usuario["password"] != datos.password:
        raise HTTPException(status_code=401, detail="Credenciales inválidas")
    return {"token": datos.username}


@app.get("/catalogo")
def catalogo():
    return CATALOGO


@app.get("/pedidos/{pedido_id}")
def obtener_pedido(pedido_id: int, request: Request):
    usuario_desde_token(request)
    pedido = PEDIDOS.get(pedido_id)
    if not pedido:
        raise HTTPException(status_code=404, detail="Pedido no encontrado")
    # FALLO: no se verifica que el pedido pertenezca al usuario (IDOR/BOLA).
    return pedido


@app.get("/admin/usuarios")
def listar_usuarios(request: Request):
    usuario_desde_token(request)
    # FALLO: no se verifica el rol y se exponen las contraseñas.
    return [
        {"usuario": nombre, "rol": datos["rol"], "password": datos["password"]}
        for nombre, datos in USUARIOS_DEMO.items()
    ]
