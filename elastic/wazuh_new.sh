#!/bin/bash

set -exf

wazuh_master_ip=$(cat /tmp/wazuh_cf_settings | grep '^WazuhMasterIP:' | cut -d' ' -f2)
wazuh_api_user=$(cat /tmp/wazuh_cf_settings | grep '^WazuhApiAdminUsername:' | cut -d' ' -f2)
wazuh_api_password=$(cat /tmp/wazuh_cf_settings | grep '^WazuhApiAdminPassword:' | cut -d' ' -f2)
wazuh_api_port=$(cat /tmp/wazuh_cf_settings | grep '^WazuhApiPort:' | cut -d' ' -f2)

curl -Lo jre-8-linux-x64.rpm --header "Cookie: oraclelicense=accept-securebackup-cookie" "https://download.oracle.com/otn-pub/java/jdk/8u191-b12/2787e4a523244c269598db4e85c51e0c/jre-8u191-linux-x64.rpm"

rpm -qlp jre-8-linux-x64.rpm > /dev/null 2>&1 || $(echo "Unable to download JRE. Exiting." && exit 1)

yum -y install jre-8-linux-x64.rpm
rm -f jre-8-linux-x64.rpm

rpm --import https://packages.elastic.co/GPG-KEY-elasticsearch

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

yum -y install elasticsearch-6.4.2

chkconfig --add elasticsearch

curl https://raw.githubusercontent.com/wazuh/wazuh/3.6/extensions/elasticsearch/wazuh-elastic6-template-alerts.json | curl -XPUT 'http://localhost:9200/_template/wazuh' -H 'Content-Type: application/json' -d @-

yum -y install logstash-6.4.2

curl -so /etc/logstash/conf.d/01-wazuh.conf https://raw.githubusercontent.com/wazuh/wazuh/3.6/extensions/logstash/01-wazuh-remote.conf

sed -i "s/LS_GROUP=logstash/LS_GROUP=ossec/" /etc/logstash/startup.options

initctl start logstash

yum -y install kibana-6.4.2

export NODE_OPTIONS="--max-old-space-size=3072"

sudo -u kibana /usr/share/kibana/bin/kibana-plugin install https://packages.wazuh.com/wazuhapp/wazuhapp-3.6.1_6.4.2.zip

# Configuring kibana.yml
sed -i "s/# server.host: "localhost"/server.host: "0.0.0.0"/" /etc/kibana/kibana.yml

chkconfig --add kibana

# Configuring Wazuh API in Kibana plugin
api_config="/tmp/api_config.json"
api_time=$(($(date +%s%N)/1000000))

cat > ${api_config} << EOF
{
  "api_user": "wazuh_api_user",
  "api_password": "wazuh_api_password",
  "url": "https://wazuh_master_ip",
  "api_port": "wazuh_api_port",
  "insecure": "false",
  "component": "API",
  "cluster_info": {
    "manager": "wazuh-manager",
    "cluster": "disabled",
    "status": "disabled"
  }
}
EOF

sed -i "s/wazuh_api_user/${wazuh_api_user}/" ${api_config}
sed -i "s/wazuh_api_password/${wazuh_api_password}/" ${api_config}
sed -i "s/wazuh_master_ip/${wazuh_master_ip}/" ${api_config}
sed -i "s/wazuh_api_port/${wazuh_api_port}/" ${api_config}

rm -f ${api_config}

service kibana start

sed -i "s/^enabled=1/enabled=0/" /etc/yum.repos.d/elastic.repo
