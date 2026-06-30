# The Effects of SSH Fingerprintability

This repository contains the code and configuration files used in the paper "The Effects of SSH Fingerprintability" for the `CS4710 Research in Cyber Security – Hacking Lab (2025/26 Q4)` course at TU Delft.

## Deploying the honeypots

Use Docker Compose to deploy the honeypots.

First, modify the `docker-compose.yml` file to configure each honeypot to listen on the desired IP address. By default, the honeypots only listen on a single private IP address. You can assign multiple IP addresses by joining them with a newline character (`\n`).

To deploy Splunk and the honeypots, run the following command in the root directory of this repository:

```sh
docker compose up --build -d
```

Make sure to check the logs of each honeypot to ensure attackers are running commands on them. You can view the logs using the following command:

```sh
docker compose logs -f <honeypot_name>
```

To stop a honeypot without stopping Splunk or the other honeypots, run the following command:

```sh
docker compose stop <honeypot_name>
```

## Adding new honeypots

To add a new honeypot, create a new configuration directory in the `config` folder. You can copy an existing configuration directory and modify it as needed. Then, add a new service to the `docker-compose.yml` file for the new honeypot, specifying the appropriate configuration files and environment variables.

You MUST also create the corresponding output directories in the `outputs` folder for the new honeypot:

```sh
mkdir -p outputs/<honeypot_name>/log
mkdir -p outputs/<honeypot_name>/state/downloads
mkdir -p outputs/<honeypot_name>/state/tty
```

If these directories are not created, or if they are not writable by the Docker container, the honeypot will still log connection and login events. However, the moment a shell is created or a command is executed, the honeypot will silently fail without any errors being appended to the log files.
