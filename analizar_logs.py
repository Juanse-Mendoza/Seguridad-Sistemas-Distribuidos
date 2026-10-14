"""Análisis de eventos sospechosos a partir de audit.log (monitoreo y auditoría).

Reglas simples, alineadas con las alertas diseñadas en la Fase 2:
  - 3 o más LOGIN_FALLIDO desde una IP            -> posible fuerza bruta
  - Cualquier ACCESO_DENEGADO_OBJETO              -> intento de acceso a recursos ajenos
  - Cualquier ACCESO_DENEGADO_ROL                 -> intento de escalar privilegios
  - 5 o más RATE_LIMIT_EXCEDIDO desde una IP      -> posible DoS
  - Cualquier TOKEN_INVALIDO                      -> token falsificado o manipulado
"""

import json
import sys
from collections import Counter, defaultdict


def cargar(ruta: str = "audit.log") -> list[dict]:
    eventos = []
    try:
        with open(ruta, encoding="utf-8") as archivo:
            for linea in archivo:
                if linea.strip():
                    eventos.append(json.loads(linea))
    except FileNotFoundError:
        pass
    return eventos


def analizar(ruta: str = "audit.log") -> None:
    eventos = cargar(ruta)
    print(f"\n=== Análisis de eventos ({len(eventos)} registros en {ruta}) ===")
    if not eventos:
        print("No hay eventos registrados.")
        return

    print("\nEventos por tipo:")
    for evento, total in Counter(e["evento"] for e in eventos).most_common():
        print(f"  {evento:<26} {total}")

    por_ip = defaultdict(Counter)
    for e in eventos:
        por_ip[e["ip"]][e["evento"]] += 1
        # Se separan los bloqueos del login (fuerza bruta) de los del resto de la API (DoS).
        if e["evento"] == "RATE_LIMIT_EXCEDIDO":
            por_ip[e["ip"]]["BLOQUEO_LOGIN" if e["detalle"] == "login" else "BLOQUEO_API"] += 1

    alertas = []
    for ip, conteo in por_ip.items():
        intentos_login = conteo["LOGIN_FALLIDO"] + conteo["BLOQUEO_LOGIN"]
        if intentos_login >= 3:
            alertas.append(
                f"[ALTA] Posible fuerza bruta desde {ip}: {conteo['LOGIN_FALLIDO']} logins fallidos "
                f"y {conteo['BLOQUEO_LOGIN']} intentos bloqueados"
            )
        if conteo["BLOQUEO_API"] >= 5:
            alertas.append(f"[ALTA] Posible DoS desde {ip}: {conteo['BLOQUEO_API']} solicitudes bloqueadas")
        if conteo["TOKEN_INVALIDO"] >= 1:
            alertas.append(f"[MEDIA] Token inválido o falsificado desde {ip}: {conteo['TOKEN_INVALIDO']} veces")

    for e in eventos:
        if e["evento"] == "ACCESO_DENEGADO_OBJETO":
            alertas.append(
                f"[ALTA] Usuario '{e['usuario']}' intentó leer un recurso ajeno ({e['detalle']}) desde {e['ip']}"
            )
        if e["evento"] == "ACCESO_DENEGADO_ROL":
            alertas.append(
                f"[MEDIA] Usuario '{e['usuario']}' intentó acceder a {e['ruta']} sin rol suficiente"
            )

    print("\nAlertas generadas:")
    if alertas:
        for alerta in alertas:
            print(f"  {alerta}")
    else:
        print("  Sin alertas.")


if __name__ == "__main__":
    analizar(sys.argv[1] if len(sys.argv) > 1 else "audit.log")
