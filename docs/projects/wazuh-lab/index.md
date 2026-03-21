# Wazuh Lab

## Overview

This project documents the deployment of a dedicated Wazuh all-in-one instance on an Ubuntu VM running on Proxmox. The goal was to build a cleaner and more realistic SIEM lab than my previous Docker-based deployment on a Synology NAS, onboard Windows and Linux endpoints, validate centralized monitoring across multiple systems, implement some integrations and rebuild an Active Directory structure.

## Why Wazuh

Before building the lab, I evaluated several SIEM options. Splunk offers strong detection and SPL, but licensing costs make it impractical for a home lab at meaningful data volumes. Elastic Stack is powerful but requires significant tuning and lacks built-in security modules out of the box. Microsoft Sentinel requires Azure infrastructure and I preferred an on-prem solution. I chose Wazuh because it provides endpoint monitoring, log collection, FIM, active response, vulnerability detection, CIS benchmarking, and native MITRE ATT&CK mapping in a single open-source platform with no license constraints.

## Project Goals

The main objectives of this project were to:

* move Wazuh from a shared Docker environment to a dedicated VM
* isolate security tooling from general homelab services
* onboard and validate endpoints from multiple operating systems
* build a foundational Windows Server and Active Directory monitoring
* explore SIEM-specific features (integrations, FIM, decoders/rules, etc.)

## Environment Summary

The Wazuh environment is deployed as a single-node all-in-one installation on a dedicated Ubuntu VM hosted on Proxmox.

Initial monitored systems include:

| Hostname | Operating System | Role | IP Address | VLAN |
| :----------------------- | :---------------------- | :-------------------------- | :--------------- | :----------------------- |
| `home-lab-wazuh-01` | Ubuntu Server 22.04 | SIEM Server | `192.168.10.2` | VLAN 10 (Lab-Security) |
| `home-home-paw-01` | Windows 11 | Personal Workstation | DHCP | VLAN 2 (Home) |
| `home-lab-dc-01` | Windows Server 2025 | Domain Controller | `192.168.10.4` | VLAN 10 (Lab-Security) |
| `home-lab-client-01` | Windows 11 Enterprise | Lab Client | `192.168.10.5` | VLAN 10 (Lab-Security) |
| `home-lab-ubuntu-01` | Ubuntu Server 22.04 | Lab Server | `192.168.10.3` | VLAN 10 (Lab-Security) |
| `home-home-adguard-01` | DietPi (Debian) | Docker Host / DNS / VPN | `192.168.2.5` | VLAN 2 (Home) |

## Architecture

![Wazuh Lab Architecture](./assets/diagrams/wazuh-architecture-light.png#only-light)
![Wazuh Lab Architecture](./assets/diagrams/wazuh-architecture-dark.png#only-dark)

## Implementation Overview

The project was implemented in the following phases:

1. **[Core Deployment](core-deployment.md)** — provisioning the Wazuh server VM, installing all components, configuring network access, and onboarding Windows and Linux agents
2. **[Integrations](integrations.md)** — VirusTotal integration for file hash enrichment and automated active response for malicious file removal
3. **[Telemetry](telemetry.md)** — Sysmon for Windows and Linux, AD audit policy hardening, Docker event monitoring, and CIS Docker benchmark checks
4. **[Detection Rules](detection-rules.md)** — custom rules for SharpHound AD reconnaissance and PowerShell abuse techniques, with MITRE ATT&CK mapping
5. **[Dashboards](dashboards.md)** — Active Directory security, VirusTotal activity, and anomaly detection dashboards

Each phase is documented on its own page with configuration details, validation steps, and observations.

## Challenges and Lessons Learned

Some of the main issues during deployment were:

??? warning "VLAN routing issue — missing static route on Fritzbox"

    After creating VLAN 10 (Lab-Security) for the lab environment, systems on that network were unable to reach the internet for updates. The root cause was a missing static route on the upstream gateway (Fritzbox). Because the network path is Internet → Fritzbox → UniFi Gateway → internal VLANs, the Fritzbox had no return route for the new 192.168.10.0/24 subnet. Adding a static route on the Fritzbox pointing to the UniFi Gateway resolved the issue. This reinforced the importance of validating routing tables across all network hops when adding new segments, not just the local gateway.

??? warning "Missing Docker events — known bug"

    I also spent some time troubleshooting the missing Docker events till I came across the bug explained in the [Docker section](telemetry.md#docker-integration)