#!/bin/bash
# Install Kibana instance using Cloudformation template
# Support for Amazon Linux

set -exf

elastic_version=$(cat /tmp/wazuh_cf_settings | grep '^Elastic_Wazuh:' | cut -d' ' -f2 | cut -d'_' -f1)
wazuh_version=$(cat /tmp/wazuh_cf_settings | grep '^Elastic_Wazuh:' | cut -d' ' -f2 | cut -d'_' -f2)
wazuh_api_user=$(cat /tmp/wazuh_cf_settings | grep '^WazuhApiAdminUsername:' | cut -d' ' -f2)
wazuh_api_password=$(cat /tmp/wazuh_cf_settings | grep '^WazuhApiAdminPassword:' | cut -d' ' -f2)
kibana_dns=$(cat /tmp/wazuh_cf_settings | grep '^KibanaDNS:' | cut -d' ' -f2)

# Check if running as root
if [[ $EUID -ne 0 ]]; then
   echo "This script must be run as root"
   exit 1
fi

# Adding Wazuh repository
wazuh_major_version=$(echo ${wazuh_version} | cut -d'.' -f1)
cat > /etc/yum.repos.d/wazuh.repo << EOF
[wazuh_repo]
gpgcheck=1
gpgkey=https://packages.wazuh.com/key/GPG-KEY-WAZUH
enabled=1
name=Wazuh repository
baseurl=https://packages.wazuh.com/${wazuh_major_version}.x/yum/
protect=1
EOF

# Configuring Elastic repository
rpm --import https://packages.elastic.co/GPG-KEY-elasticsearch
elastic_major_version=$(echo ${elastic_version} | cut -d'.' -f1)
cat > /etc/yum.repos.d/elastic.repo << EOF
[elasticsearch-${elastic_major_version}.x]
name=Elasticsearch repository for ${elastic_major_version}.x packages
baseurl=https://artifacts.elastic.co/packages/${elastic_major_version}.x/yum
gpgcheck=1
gpgkey=https://artifacts.elastic.co/GPG-KEY-elasticsearch
enabled=1
autorefresh=1
type=rpm-md
EOF

# Installing wazuh-manager
yum -y install wazuh-manager-${wazuh_version}
chkconfig --add wazuh-manager

# Enable registration service (only for master node)
/var/ossec/bin/ossec-control enable auth

# Restart wazuh-manager
service wazuh-manager restart

# Installing NodeJS
curl --silent --location https://rpm.nodesource.com/setup_8.x | bash -
yum -y install nodejs

# Installing wazuh-api
yum -y install wazuh-api-${wazuh_version}
chkconfig --add wazuh-api

# Configuring Wazuh API user and password
cd /var/ossec/api/configuration/auth
node htpasswd -b -c user ${wazuh_api_user} ${wazuh_api_password}

# Enable Wazuh API SSL
api_ssl_dir="/var/ossec/api/configuration/ssl"
openssl req -x509 -batch -nodes -days 3650 -newkey rsa:2048 -keyout ${api_ssl_dir}/server.key -out ${api_ssl_dir}/server.crt
sed -i "s/config.https = \"no\";/config.https = \"yes\";/" /var/ossec/api/configuration/config.js

# Restart wazuh-api
service wazuh-api restart

# Installing Filebeat
yum -y install filebeat
chkconfig --add filebeat

# Configuring Filebeat
curl -so /etc/filebeat/filebeat.yml https://raw.githubusercontent.com/wazuh/wazuh/v${wazuh_version}/extensions/filebeat/filebeat.yml

cat > /etc/filebeat/filebeat.yml << EOF
filebeat:
 prospectors:
  - type: log
    enabled: true
    paths:
     - "/var/ossec/logs/alerts/alerts.json"
    document_type: json
    json.message_key: log
    json.keys_under_root: true
    json.overwrite_keys: true

output:
 logstash:
   # The Logstash hosts
   hosts: ["${kibana_dns}:5000"]
#   ssl:
#     certificate_authorities: ["/etc/filebeat/logstash.crt"]
EOF

service filebeat start

# Disable repositories
sed -i "s/^enabled=1/enabled=0/" /etc/yum.repos.d/elastic.repo
sed -i "s/^enabled=1/enabled=0/" /etc/yum.repos.d/wazuh.repo
