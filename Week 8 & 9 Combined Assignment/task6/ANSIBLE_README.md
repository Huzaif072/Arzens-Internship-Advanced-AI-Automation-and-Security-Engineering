# Ansible Hardening & Compliance

This playbook is designed for Ubuntu/Debian hosts created by the Terraform task. It is idempotent: package, service, line, copy, and UFW modules converge state without repeating changes.

## Prerequisites
Install Ansible and the required collection:
```bash
ansible-galaxy collection install community.general
```
Replace the example host and SSH key in `hosts.ini`. Test connectivity with `ansible webservers -m ping`.

## Run
```bash
ansible-playbook site.yml --check --diff
ansible-playbook site.yml
ansible-playbook security.yml
```
The roles update packages, set UTC, configure logging, enable unattended upgrades, enforce key-only SSH with no root login, deny inbound traffic by default, allow only 22/80/443, enable fail2ban and auditd, and generate a compliance report at `/var/log/arzens-compliance-report.txt`. Review the sample `compliance_report.txt` for the expected format.

Run with an approved maintenance window because SSH and firewall changes can disconnect an incorrectly configured host. Store private keys outside the repository and use Ansible Vault or a secrets manager for any future sensitive variables.
