# Repositorio para la entrega de los proyectos de la asignatura Redes de Computadoras correspondiente al curso 2025

## Pautas Generales:

1. Los proyectos se organizarán por equipos con un máximo de 2 integrantes cada uno.

2. Solo se considerara válida la entrega mediante un issue/pull requests al presente repositorio anterior a la fecha límite de entrega.

3. Solo se permite el empleo de la biblioteca estándar del lenguaje de programación empleado para su solución. Se descarta el empleo de cualquier biblioteca de 3ros.

4. El trabajo se valida contra el historial de git correspondiente al repo solución provisto dentro de las fechas permitidas.

5. Ante cualquier duda de implementación o propuesta de modificación de los requerimientos del proyecto que no cuente con un aval de alguno de los miembros del claustro, se asume la variante más compleja de la interrogante.

## Formato de Entrega:

Nombre del proyecto:

Nombre del 1mer integrante del equipo

Nombre del 2do integrante del equipo

Link al repo de github que contiene la solución propuesta

## Primer Proyecto

[LinkChat](linkchat.md) 

Fecha de entrega 12 de octubre 11:59:59 pm

## Quick test using Docker (bridge, privileged) — recommended for laptops on Wi‑Fi

If you can't or don't want to create a macvlan network (common on Wi‑Fi), use the provided
`docker-compose.bridge.yml` which runs two privileged containers that can open raw sockets.

Build and run (in the repo root):

	docker compose -f docker-compose.bridge.yml build
	sudo docker compose -f docker-compose.bridge.yml up

Open two new terminals and run the CLI in each container:

	docker exec -it linkchat_node_a python3 -u linkchat/cli.py
	docker exec -it linkchat_node_b python3 -u linkchat/cli.py

Then in each CLI: `iface` → choose interface (0) → `start` on one of them, and from the other `send <MAC_of_first> <message>`.

When finished, stop with Ctrl+C and remove containers with:

	docker compose -f docker-compose.bridge.yml down

