# Probes

## Manual localhost fixture

`fixture_server.py` is a standalone, manual-only HTTP fixture. Current probes and CI do not use it.

Run it from the repository root:

```sh
python3 probes/fixture_server.py
```

It listens only on `127.0.0.1`, using port `18091` by default. To select another port, pass it as the first argument, for example `python3 probes/fixture_server.py 18092`. Send a GET request to `/` to receive HTTP `200` with a JSON response:

```json
{"ok": true, "data": "AGENT TRAFFIC THROUGH SHIELD", "source": "fixture-local"}
```

Press Ctrl+C to stop the server.
