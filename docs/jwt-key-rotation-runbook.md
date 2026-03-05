# Runbook: JWT Key Rotation

Este runbook define una rotacion segura para `JWT_KEYSET` (Ed25519) sin downtime de validacion.

## Pre-checks

- Verificar que la nueva clave tenga par valido `private/public` y `kid` unico.
- Confirmar que `JWT_PRIMARY_KID` actual existe en `JWT_KEYSET` antes de cambios.
- Alinear la ventana de convivencia con `ACCESS_TTL_SECONDS` (minimo 1x TTL de access token; recomendado 2x para margen operativo).

## 1) Introducir nueva clave (sin cambiar primaria)

- Agregar nueva entrada al `JWT_KEYSET` con `kid` nuevo y ambos paths (`private/public`).
- Mantener `JWT_PRIMARY_KID` apuntando al `kid` anterior.
- Deploy y validar que `/.well-known/jwks.json` publique ambas claves activas.

Resultado esperado:
- Tokens nuevos siguen saliendo con `kid` viejo.
- Validacion acepta `kid` viejo y `kid` nuevo si aparecen.

## 2) Cambiar primaria a la nueva clave

- Actualizar `JWT_PRIMARY_KID` al `kid` nuevo.
- Mantener la clave anterior en `JWT_KEYSET` (al menos con public key).
- Deploy y verificar que los nuevos tokens se emiten con el `kid` nuevo.

Resultado esperado:
- Emision usa la clave nueva.
- Tokens emitidos previamente con `kid` viejo siguen validando durante la convivencia.

## 3) Ventana de convivencia

- Conservar ambas claves publicas en `JWT_KEYSET` durante toda la ventana.
- Monitorear errores de validacion JWT (`invalid jwt kid` / `401`) y volumen por `kid` en consumidores.
- No retirar la clave vieja hasta confirmar expiracion natural de tokens viejos.

## 4) Retiro de clave vieja

- Remover la clave vieja del `JWT_KEYSET`.
- Mantener `JWT_PRIMARY_KID` en la clave nueva.
- Deploy y monitorear picos de `401` para detectar clientes desfasados.

Resultado esperado:
- Tokens con `kid` viejo dejan de validar.
- Solo queda activa la clave nueva en JWKS.

## Rollback Guidance

Si hay incidente tras cambiar primaria o retirar clave vieja:

- Reintroducir la clave vieja en `JWT_KEYSET` (public key minima; private key si se necesita volver a firmar con ella).
- Si hay fallo de emision con la nueva clave, restaurar `JWT_PRIMARY_KID` al `kid` previo.
- Re-deploy y confirmar:
  - JWKS vuelve a publicar la clave de rollback.
  - Los tokens afectados vuelven a validar.
- Abrir RCA antes de reintentar retiro definitivo.

## Checklist de validacion operativa

- [ ] `GET /.well-known/jwks.json` lista exactamente los `kid` esperados para la fase actual.
- [ ] Token nuevo emitido despues del cambio de primaria trae `kid` nuevo en header.
- [ ] Durante convivencia, un token firmado con `kid` viejo valida correctamente.
- [ ] Tras retiro, token firmado con `kid` viejo falla validacion (`invalid jwt kid`).
- [ ] No hay incremento anormal sostenido de `401` post-deploy.
