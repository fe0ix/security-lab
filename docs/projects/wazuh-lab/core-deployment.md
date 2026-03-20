# Core Deployment

## Wazuh Indexer Installation

I used the Wazuh installation assistant to generate the required configuration files and deploy the indexer on the dedicated Ubuntu VM.

### Key commands

```shell
curl -sO https://packages.wazuh.com/4.14/wazuh-install.sh
curl -sO https://packages.wazuh.com/4.14/config.yml
nano config.yml
# The default `config.yml` was adjusted so that the indexer, server, and dashboard components used the correct IP address of the dedicated Wazuh VM.
sudo bash wazuh-install.sh --generate-config-files
sudo bash wazuh-install.sh --wazuh-indexer node-1
sudo bash wazuh-install.sh --start-cluster
```

### Validation

After the installation, I validated that the indexer was reachable and the cluster started successfully.

```shell
sudo tar -axf wazuh-install-files.tar wazuh-install-files/wazuh-passwords.txt -O | grep -P "\'admin\'" -A 1
curl -k -u admin https://192.168.10.2:9200
curl -k -u admin https://192.168.10.2:9200/_cat/nodes?v
```

### Result

The Wazuh indexer responded on port `9200`, the node was visible as `node-1`, and the cluster initialized successfully.

***

## Wazuh Server Installation

After the indexer was working, I installed the Wazuh server component.

### Key command

```shell
sudo bash wazuh-install.sh --wazuh-server wazuh-1
```

### Result

The installation completed successfully and also installed and configured Filebeat automatically.

This step included:

* Wazuh manager installation
* vulnerability detection configuration
* Filebeat installation
* Filebeat service startup

***

## Wazuh Dashboard Installation

The final core component was the Wazuh Dashboard.

### Key command

```shell
sudo bash wazuh-install.sh --wazuh-dashboard dashboard
```

### Result

The dashboard installation completed successfully and the web interface became available on:

```
https://192.168.10.2:443
```

## Security considerations

After deployment, I followed some steps of the [Securing the Wazuh server API](https://documentation.wazuh.com/current/user-manual/api/securing-api.html) guide and changed the credentials of the default accounts `wazuh` and `wazuh-wui`. In a production environment, additional hardening steps would include restricting indexer API access to the Wazuh server only, enforcing a TLS minimum version of 1.2, replacing the default self-signed certificate with a trusted one, and enabling audit logging on the indexer. Further steps would include hardening the underlying OS against CIS benchmarks and applying [RBAC](https://documentation.wazuh.com/current/user-manual/api/rbac/index.html#role-based-access-control) with least-privilege access to the Wazuh API. These were not implemented in this lab as the environment is isolated within a dedicated VLAN with firewall-restricted access.

***

## Network and Firewall Configuration

Before onboarding the first agents, I reviewed the required ports for communication between Wazuh components and agents.

For this setup:

* all Wazuh core components run on the same VM
* no separate firewall rules were required between the internal Wazuh components
* only agent-to-server communication needed to be allowed
* dashboard access was restricted to my own workstation

### Network overview

* **VLAN 2 (Home):** allowed agent traffic to the Wazuh server
* **VLAN 10 (Lab-Security):** contains the Wazuh VM itself and additional lab systems such as `home-lab-dc-01` , `home-lab-ubuntu-01` and `home-lab-client-01`


![Wazuh agent traffic network object](./assets/screenshots/network-firewall-object.png){ width="300" }
/// caption
Required ports for Wazuh agent communication
///

![Wazuh agent traffic network object](./assets/screenshots/agent-firewall-rules.png){ width="1100" .zoomable loading=lazy }
/// caption
Wazuh agent firewall rules
///


## Agent Deployment

### Windows

I first deployed a Windows agent on my own workstation `home-home-paw-01`. The installation process was straightforward, and I followed the official Wazuh documentation for [Windows agent deployment](https://documentation.wazuh.com/current/installation-guide/wazuh-agent/wazuh-agent-package-windows.html#deploying-wazuh-agents-on-windows-endpoints). After completing the installation and configuration steps, the agent successfully connected to the Wazuh manager and appeared in the dashboard.


![First Windows agent visible in Wazuh](./assets/screenshots/first-agent-windows-client.png){ width="1100" .zoomable loading=lazy }
/// caption
First Windows agent visible in Wazuh
///

***

### Linux

The [Linux agent deployment](https://documentation.wazuh.com/current/installation-guide/wazuh-agent/wazuh-agent-package-linux.html#deploying-wazuh-agents-on-linux-endpoints) process was similar to the Windows deployment. The main difference was selecting the correct package for the target distribution and CPU architecture.

After installation, the Linux agent also appeared successfully in the Wazuh dashboard.

***

### Additional agent onboarding

After the first successful deployments, I repeated the same onboarding steps for the following systems:

* `home-lab-dc-01`
* `home-lab-client-01`
* `home-lab-ubuntu-01`

***

### Current agent overview

![Current agent overview](./assets/screenshots/active-agents.png){ width="1100" .zoomable loading=lazy }
/// caption
///

***

### Observations

Manual agent deployment is straightforward for a small number of systems. For larger environments, more scalable deployment methods are more practical, such as:

* [Windows agent deployment via Group Policy](https://wazuh.com/blog/deploying-wazuh-agent-using-windows-gpo/)
* [Linux agent deployment via Ansible](https://wazuh.com/blog/configuration-management-endpoints-using-ansible/)