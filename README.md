# VBR Configuration Collector

PowerShell script that discovers the latest Swagger API version on a Veeam Backup & Replication server and collects configuration data via the REST API. Designed for auditing, support and troubleshooting scenarios.

### Features

- Dynamic Swagger discovery — automatically detects available API versions from the Swagger UI endpoints, with a hardcoded fallback list for offline or restricted environments.
- Excludes sensitive endpoints (credentials, encryption passwords, user data, certificates) and supports context-aware data masking with a reversible mapping file.
- Single-file JSON export — all collected endpoint data exported to a formatted JSON file with metadata (timestamps, version info, success/failure counts).

## 📗 Documentation

Run the script in PowerShell:
powershell   .\Veeam_Config_Collector.ps1

Enter the VBR server address, port (default: 9419), and credentials when prompted
Choose output location and whether to enable data masking
The script collects data from all parameter-free GET endpoints and exports the results

### Requirements

PowerShell 5.1 or later
Network access to the VBR REST API (default port 9419)
Valid VBR credentials with API access

## ✍ Contributions

We encourage you to create [issues](https://github.com/VeeamHub/veeam-config-collector/issues/new/choose) for Bugs & Feature Requests and submit Pull Requests.

## 🤝🏾 License

* [MIT License](LICENSE)

## 🤔 Questions

If you have any questions or something is unclear, please don't hesitate to [create an issue](https://github.com/VeeamHub/veeam-config-collector/issues/new/choose) and let us know!
