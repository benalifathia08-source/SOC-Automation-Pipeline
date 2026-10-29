#!/bin/bash
# Tools VM base setup (run with sudo). Safe to re-run.
#   1. Hostname "tools"
#   2. Docker from Ubuntu's own archive (docker.io + docker-compose-v2). No user is added to the docker
#      group: that group is root-equivalent, and automation already uses sudo.
#   3. Host firewall (ufw): SSH (22) and n8n (5678) from the lab subnet only
#   4. Pipeline log folder /var/log/soc-pipeline, written by n8n (container uid 1000), read by the Wazuh agent
#   5. Static IP 192.168.145.20 (outside VMware's DHCP range), applied LAST and detached because it
#      drops this SSH session. Reconnect to 192.168.145.20 afterwards.
#      Revert: rm /etc/netplan/99-lab-static.yaml /etc/cloud/cloud.cfg.d/99-lab-disable-network.cfg; netplan apply
set -e
LAB=192.168.145.0/24
IP=192.168.145.20
GW=192.168.145.2          # VMware NAT gateway and DNS proxy

echo "== hostname"
hostnamectl set-hostname tools
grep -q '^127.0.1.1 tools$' /etc/hosts || sed -i 's/^127\.0\.1\.1 .*/127.0.1.1 tools/' /etc/hosts
grep -q '^127.0.1.1 ' /etc/hosts || echo '127.0.1.1 tools' >> /etc/hosts
hostname

echo "== docker"
if ! command -v docker > /dev/null; then
    apt-get update -q
    DEBIAN_FRONTEND=noninteractive apt-get install -y -q docker.io docker-compose-v2
fi
systemctl enable --now docker > /dev/null
docker --version
docker compose version

echo "== firewall"
ufw --force reset > /dev/null
ufw default deny incoming > /dev/null
ufw default allow outgoing > /dev/null
ufw allow from $LAB to any port 22 proto tcp comment 'lab ssh' > /dev/null
ufw allow from $LAB to any port 5678 proto tcp comment 'lab n8n' > /dev/null
ufw --force enable > /dev/null
ufw status numbered

echo "== pipeline log folder"
install -d -o 1000 -g 1000 -m 0750 /var/log/soc-pipeline
ls -ld /var/log/soc-pipeline

echo "== static IP $IP"
IFACE=$(ip -o -4 route show to default | awk '{print $5; exit}')
echo "interface: $IFACE"
echo 'network: {config: disabled}' > /etc/cloud/cloud.cfg.d/99-lab-disable-network.cfg
cat > /etc/netplan/99-lab-static.yaml <<EOF
# Lab: fixed address so the Wazuh integration URL and firewall rules stay valid
network:
  version: 2
  ethernets:
    $IFACE:
      dhcp4: false
      addresses: [$IP/24]
      routes:
        - to: default
          via: $GW
      nameservers:
        addresses: [$GW]
EOF
chmod 600 /etc/netplan/99-lab-static.yaml
netplan generate
echo "applying in 3 s; this SSH session will drop. Reconnect to $IP"
nohup sh -c 'sleep 3; netplan apply' > /dev/null 2>&1 &
