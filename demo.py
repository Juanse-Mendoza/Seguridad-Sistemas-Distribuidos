"""Demostración: configuración vulnerable vs. configuración protegida.

Arranca las dos APIs en 127.0.0.1 (puertos 8001 y 8002), ejecuta los mismos
escenarios contra ambas y muestra una tabla comparativa.

Uso:  python demo.py
Solo debe ejecutarse en un entorno propio y local, con los datos ficticios incluidos.
"""

import os
import socket
import subprocess
import sys
import time
from collections import Counter

import requests

from analizar_logs import analizar

BASES = {
    "vulnerable": "http://127.0.0.1:8001",
    "protegida": "http://127.0.0.1:8002",
}
CLAVES = {"ana": "Ana#2024", "beto": "Beto#2024", "admin": "Admin#2024"}

sesion = requests.Session()
sesion.trust_env = False  # evita que un proxy del sistema interfiera con localhost


# ----------------------------------------------------------------- Utilidades
def esperar_puerto(puerto: int, intentos: int = 50) -> None:
    for _ in range(intentos):
        try:
            with socket.create_connection(("127.0.0.1", puerto), timeout=0.5):
                return
        except OSError:
            time.sleep(0.2)
    raise RuntimeError(f"El servidor del puerto {puerto} no arrancó")


def iniciar_servidor(modulo: str, puerto: int) -> subprocess.Popen:
    return subprocess.Popen(
        [sys.executable, "-m", "uvicorn", f"{modulo}:app",
         "--host", "127.0.0.1", "--port", str(puerto), "--log-level", "warning"]
    )


def login(base: str, usuario: str, clave: str | None = None) -> str | None:
    r = sesion.post(f"{base}/login", json={"username": usuario, "password": clave or CLAVES[usuario]})
    return r.json().get("token") if r.status_code == 200 else None


def get(base: str, ruta: str, token: str | None = None) -> requests.Response:
    cabeceras = {"Authorization": f"Bearer {token}"} if token else {}
    return sesion.get(f"{base}{ruta}", headers=cabeceras)


def resumen(codigos: list[int]) -> str:
    conteo = Counter(codigos)
    return ", ".join(f"{codigo}x{total}" for codigo, total in sorted(conteo.items()))


# ------------------------------------------------------------------ Escenarios
def esc_acceso_legitimo(base: str) -> str:
    token = login(base, "ana")
    r = get(base, "/pedidos/1", token)
    return f"HTTP {r.status_code}"


def esc_pedido_ajeno(base: str) -> str:
    token = login(base, "ana")
    r = get(base, "/pedidos/2", token)  # el pedido 2 pertenece a beto
    return f"HTTP {r.status_code}" + (" (datos ajenos expuestos)" if r.status_code == 200 else " (bloqueado)")


def esc_admin_sin_rol(base: str) -> str:
    token = login(base, "ana")
    r = get(base, "/admin/usuarios", token)
    expuesto = r.status_code == 200 and "password" in r.text
    return f"HTTP {r.status_code}" + (" (contraseñas expuestas)" if expuesto else " (bloqueado)")


def esc_token_falsificado(base: str) -> str:
    r = get(base, "/pedidos/2", "beto")  # token inventado, sin haber iniciado sesión
    return f"HTTP {r.status_code}" + (" (suplantación lograda)" if r.status_code == 200 else " (rechazado)")


def esc_fuerza_bruta(base: str) -> str:
    # Lista pequeña de contraseñas candidatas para el usuario ficticio "admin".
    candidatas = ["123456", "password", "admin", "qwerty", "Admin2024",
                  "letmein", "Admin#2024", "welcome", "abc123", "admin123"]
    codigos = []
    for intento, clave in enumerate(candidatas, start=1):
        r = sesion.post(f"{base}/login", json={"username": "admin", "password": clave})
        codigos.append(r.status_code)
        if r.status_code == 200:
            return f"contraseña descubierta en el intento {intento}"
    return f"bloqueado: {resumen(codigos)}"


def esc_inundacion(base: str) -> str:
    codigos = [get(base, "/catalogo").status_code for _ in range(50)]
    return resumen(codigos)


ESCENARIOS = [
    ("0. Acceso legítimo (pedido propio)", esc_acceso_legitimo),
    ("1. Leer pedido de otro usuario", esc_pedido_ajeno),
    ("2. Cliente accede a /admin", esc_admin_sin_rol),
    ("3. Token falsificado", esc_token_falsificado),
    ("4. Fuerza bruta de contraseña", esc_fuerza_bruta),
    ("5. Inundación de 50 solicitudes", esc_inundacion),
]


# ------------------------------------------------------------------ Principal
def main() -> None:
    if os.path.exists("audit.log"):
        os.remove("audit.log")

    servidores = [
        iniciar_servidor("app_vulnerable", 8001),
        iniciar_servidor("app_protected", 8002),
    ]
    try:
        esperar_puerto(8001)
        esperar_puerto(8002)

        resultados = []
        for nombre, funcion in ESCENARIOS:
            resultados.append((
                nombre,
                funcion(BASES["vulnerable"]),
                funcion(BASES["protegida"]),
            ))

        ancho = max(len(r[0]) for r in resultados)
        col = max(len(r[1]) for r in resultados)
        print("\n" + "=" * 100)
        print(f"{'Escenario':<{ancho}} | {'Configuración vulnerable':<{col}} | Configuración protegida")
        print("-" * 100)
        for nombre, vulnerable, protegida in resultados:
            print(f"{nombre:<{ancho}} | {vulnerable:<{col}} | {protegida}")
        print("=" * 100)

        analizar("audit.log")
    finally:
        for proceso in servidores:
            proceso.terminate()
        for proceso in servidores:
            proceso.wait(timeout=5)


if __name__ == "__main__":
    main()
