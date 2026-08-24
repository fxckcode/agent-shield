# Tarea de implementación — DKL-30: CI en GitHub Actions

## Contexto
Repo: agent-guard-proxy (Rust). Cargo package "agent-guard-proxy" v0.1.0, edition 2021.
Hoy NO existe carpeta .github/ ni workflow de CI. El probe de análisis
(`./probes/probe_dkl30_no_ci.sh`) FALLA (exit 1) porque falta el workflow; el fix
debe hacer que ese probe pase (exit 0).

## Qué implementar
1. Crear `.github/workflows/ci.yml` que corra en `push` y `pull_request`:
   - Ubuntu latest, rust stable
   - Paso: `cargo fmt --check` (formato)
   - Paso: `cargo clippy -- -D warnings` (lints estrictos)
   - Paso: `cargo test` (suite)
   - Nombre del job: `ci`. Nombres de paso claros.
2. NO tocar Cargo.toml salvo que sea imprescindible (no lo es).
3. NO cambiar código fuente Rust ni tests: el CI solo agrega la red de seguridad.
4. OUT OF SCOPE: deploy, benchmarks, matrix multiplataforma, caching.

## Criterios de aceptación
- Existe `.github/workflows/ci.yml` en el repo.
- El workflow se dispara en push y pull_request.
- Corre fmt --check, clippy -D warnings, test sobre stable.
- `./probes/probe_dkl30_no_ci.sh` pasa (exit 0) tras el cambio.
- `cargo fmt --check` local pasa; `cargo clippy -- -D warnings` local pasa;
  `cargo test` local pasa.

## Restricciones
- Solo crear el workflow y (si hace falta) `.gitignore` de `.github/` no.
- NO hacer commits ni push: dejar los archivos creados en el worktree.
- Responder al final con: lista de archivos creados, y el resultado de
  correr localmente `cargo fmt --check`, `cargo clippy -- -D warnings`,
  `cargo test` y `./probes/probe_dkl30_no_ci.sh`.