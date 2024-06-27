#!/bin/bash

# Atualiza o sistema
sudo apt update && sudo apt upgrade -y

# Instala mitmproxy usando apt
sudo apt install -y mitmproxy

# Instala ufw se não estiver instalado
sudo apt install -y ufw

# Configura regras do ufw
sudo ufw default deny incoming
sudo ufw default allow outgoing
sudo ufw allow 22  # SSH
sudo ufw allow 80  # HTTP
sudo ufw allow 443 # HTTPS
sudo ufw allow 7878 # Porta 7878
sudo ufw allow 7879 # Porta 7879
sudo ufw enable

# Cria o serviço systemd para mitmweb
echo "[Unit]
Description=Mitmweb Service
After=network.target

[Service]
ExecStart=/usr/bin/mitmweb --listen-host 0.0.0.0 --listen-port 7878 --web-iface 0.0.0.0 --web-port 7879 -s index.py --set block_global=false --set websocket=false
Restart=on-failure
User=nobody
Group=nogroup
StandardOutput=append:/var/log/mitmweb.log
StandardError=append:/var/log/mitmweb.log

[Install]
WantedBy=multi-user.target" | sudo tee /etc/systemd/system/mitmweb.service > /dev/null

# Recarga o systemd e habilita o serviço
sudo systemctl daemon-reload
sudo systemctl enable mitmweb.service
sudo systemctl start mitmweb.service

# Confirmação da instalação
echo "Instalação e configuração concluídas!"
