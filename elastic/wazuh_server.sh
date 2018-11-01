#!/bin/bash

set -exf

kibana_ip=$(cat /tmp/wazuh_cf_settings | grep '^KibanaIP:' | cut -d' ' -f2 | cut -d'_' -f1)
wazuh_api_user=$(cat /tmp/wazuh_cf_settings | grep '^WazuhApiAdminUsername:' | cut -d' ' -f2)
wazuh_api_password=$(cat /tmp/wazuh_cf_settings | grep '^WazuhApiAdminPassword:' | cut -d' ' -f2)

# Check if running as root
if [[ $EUID -ne 0 ]]; then
   echo "This script must be run as root"
   exit 1
fi

cat > /etc/yum.repos.d/wazuh.repo <<\EOF
[wazuh_repo]
gpgcheck=1
gpgkey=https://packages.wazuh.com/key/GPG-KEY-WAZUH
enabled=1
name=Wazuh repository
baseurl=https://packages.wazuh.com/3.x/yum/
protect=1
EOF

yum install wazuh-manager

curl --silent --location https://rpm.nodesource.com/setup_8.x | bash -

yum install nodejs

yum install wazuh-api

rpm --import https://packages.elastic.co/GPG-KEY-elasticsearch

# Configuring Wazuh API user and password
cd /var/ossec/api/configuration/auth
node htpasswd -b -c user ${wazuh_api_user} ${wazuh_api_password}

# Enable Wazuh API SSL
api_ssl_dir="/var/ossec/api/configuration/ssl"
openssl req -x509 -batch -nodes -days 3650 -newkey rsa:2048 -keyout ${api_ssl_dir}/server.key -out ${api_ssl_dir}/server.crt
sed -i "s/config.https = \"no\";/config.https = \"yes\";/" /var/ossec/api/configuration/config.js

# Restart wazuh-api
service wazuh-api restart

cat > /etc/yum.repos.d/elastic.repo << EOF
[elasticsearch-6.x]
name=Elasticsearch repository for 6.x packages
baseurl=https://artifacts.elastic.co/packages/6.x/yum
gpgcheck=1
gpgkey=https://artifacts.elastic.co/GPG-KEY-elasticsearch
enabled=1
autorefresh=1
type=rpm-md
EOF

yum install filebeat-6.4.2

curl -so /etc/filebeat/filebeat.yml https://raw.githubusercontent.com/wazuh/wazuh/3.6/extensions/filebeat/filebeat.yml
sed -i "s/YOUR_ELASTIC_SERVER_IP/${kibana_ip}/" /etc/filebeat/filebeat.yml

chkconfig --add filebeat

service filebeat start
