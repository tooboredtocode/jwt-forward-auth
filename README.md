# jwt-forward-auth

This is a simple forward authentication service that uses JWTs to authenticate users.
It is designed to be used with the Traefik reverse proxy.
It may work with other reverse proxies that support forward authentication.

## Usage

### Configuration
The service has the following configuration options:
- '--listen': The address and port to bind to. Defaults to `0.0.0.0:8080`.
- `-c`, `--config`: Path to the configuration file. Defaults to `config.yml`.
- `-l`, `--log`: The log filter configuration (e.g. "info,my_crate=debug"). Defaults to `info`.
- `-a`, `--ansi`: Whether to output the log using ansi colors. Defaults to `true`.

The flags can alternatively be set with the following environment variables:
- `LISTEN_ADDRESS`: The address and port to bind to.
- `CONFIG`: Path to the configuration file.
- `JWT_FWA_LOG`: The log filter configuration.
- `JWT_FWA_PLAIN_LOG`: If set, the log will be output without ansi colors.

An example configuration file is provided in `config.example.yml`.

---

Copyright (c) 2024 tooboredtocode

All Rights Reserved
