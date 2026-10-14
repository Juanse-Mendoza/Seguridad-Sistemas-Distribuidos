"""Datos FICTICIOS compartidos por las dos versiones de la API.

No contiene datos reales ni sensibles. Solo sirve para la demostración local.
"""

USUARIOS_DEMO = {
    "ana": {"password": "Ana#2024", "rol": "cliente"},
    "beto": {"password": "Beto#2024", "rol": "cliente"},
    "admin": {"password": "Admin#2024", "rol": "admin"},
}

PEDIDOS = {
    1: {"dueno": "ana", "producto": "Teclado mecánico", "total": 120000},
    2: {"dueno": "beto", "producto": "Monitor 24 pulgadas", "total": 650000},
    3: {"dueno": "ana", "producto": "Mouse inalámbrico", "total": 45000},
}

CATALOGO = [
    {"id": 10, "nombre": "Teclado mecánico", "precio": 120000},
    {"id": 11, "nombre": "Monitor 24 pulgadas", "precio": 650000},
    {"id": 12, "nombre": "Mouse inalámbrico", "precio": 45000},
]
