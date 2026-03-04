# Audity Agent (Phase 2 Scaffold)

Estado: scaffold inicial (sin collectors productivos implementados).

## Objetivo fase 2
- Ejecutar collectors distribuidos con bajo consumo.
- Reportar evidencias firmadas al backend de Audity.

## Próximos pasos
1. Definir contrato gRPC/HTTP de ingestión.
2. Implementar collector GitHub/Cloud en Rust.
3. Añadir firma de payloads y rotación de claves.
4. Añadir CI para build/test multiplataforma.
