# EndpointAIProxy

EndpointAIProxy is a .NET client and control-plane prototype for routing supported AI agent traffic through a local endpoint proxy. It includes the client core, Windows service, macOS service scripts, control server, installer definitions, and tests.

Production addresses, credentials, certificates, and private deployment bundles are intentionally excluded from this public source tree. Configure the control origin, gateway origin, enrollment material, and signing keys through your private deployment process. Example values use the reserved `example.invalid` domain.

Build with the .NET SDK version selected by `global.json`. Windows MSI and macOS package workflows require their native build environments. Do not commit credentials, private certificates, captured request bodies, generated artifacts, or installer packages containing private configuration.
