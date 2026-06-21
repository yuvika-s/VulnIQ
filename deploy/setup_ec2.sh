#!/bin/bash
# One-shot provisioning for VulnIQ on an Amazon Linux 2023 EC2 instance.
# Run from the project root AFTER the code is at /opt/vulniq and backend/.env is filled.
#   sudo bash deploy/setup_ec2.sh
set -euo pipefail
APP=/opt/vulniq

echo "==> [1/6] system packages"
dnf install -y python3.11 python3.11-pip nginx git openssl >/dev/null

echo "==> [2/6] python venv + dependencies"
cd "$APP"
python3.11 -m venv venv
./venv/bin/pip install --upgrade pip >/dev/null
./venv/bin/pip install -r backend/requirements.txt
chown -R ec2-user:ec2-user "$APP"

echo "==> [3/6] self-signed TLS cert (replace with a real cert later)"
mkdir -p /etc/nginx/ssl
if [ ! -f /etc/nginx/ssl/vulniq.crt ]; then
  openssl req -x509 -nodes -days 825 -newkey rsa:2048 \
    -keyout /etc/nginx/ssl/vulniq.key -out /etc/nginx/ssl/vulniq.crt \
    -subj "/CN=vulniq" >/dev/null 2>&1
fi

echo "==> [4/6] nginx config"
cp deploy/nginx-ec2.conf /etc/nginx/conf.d/vulniq.conf
nginx -t

echo "==> [5/6] create RDS schema (alembic) — fetches creds from Secrets Manager"
sudo -u ec2-user bash -lc "cd $APP/backend && $APP/venv/bin/alembic upgrade head"

echo "==> [6/6] install + start services"
cp deploy/vulniq-api.service /etc/systemd/system/
systemctl daemon-reload
systemctl enable --now vulniq-api
systemctl enable --now nginx
systemctl restart nginx

echo ""
echo "DONE. Test on the box:  curl -sk https://localhost/api/health"
echo "From your VPN browser:  https://<EC2-private-IP>/dashboard.html"
