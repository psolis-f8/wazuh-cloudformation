#!/bin/bash

set -exf

elastic_version=$(cat /tmp/wazuh_cf_settings | grep '^Elastic_Wazuh:' | cut -d' ' -f2 | cut -d'_' -f1)
wazuh_version=$(cat /tmp/wazuh_cf_settings | grep '^Elastic_Wazuh:' | cut -d' ' -f2 | cut -d'_' -f2)
eth0_ip=$(/sbin/ifconfig eth0 | grep 'inet addr:' | cut -d: -f2  | cut -d' ' -f1)
kibana_port=$(cat /tmp/wazuh_cf_settings | grep '^KibanaPort:' | cut -d' ' -f2)
wazuh_master_ip=$(cat /tmp/wazuh_cf_settings | grep '^WazuhMasterIP:' | cut -d' ' -f2)
wazuh_api_user=$(cat /tmp/wazuh_cf_settings | grep '^WazuhApiAdminUsername:' | cut -d' ' -f2)
wazuh_api_password=$(cat /tmp/wazuh_cf_settings | grep '^WazuhApiAdminPassword:' | cut -d' ' -f2)
wazuh_api_port=$(cat /tmp/wazuh_cf_settings | grep '^WazuhApiPort:' | cut -d' ' -f2)

# Check if running as root
if [[ $EUID -ne 0 ]]; then
   echo "This script must be run as root"
   exit 1
fi

# Downloading and installing JRE
url_jre="https://download.oracle.com/otn-pub/java/jdk/8u191-b12/2787e4a523244c269598db4e85c51e0c/jre-8u191-linux-x64.rpm"
jre_rpm="/tmp/jre-8-linux-x64.rpm"
curl -Lo ${jre_rpm} --header "Cookie: oraclelicense=accept-securebackup-cookie" ${url_jre}
rpm -qlp ${jre_rpm} > /dev/null 2>&1 || $(echo "Unable to download JRE. Exiting." && exit 1)
yum -y localinstall ${jre_rpm} && rm -f ${jre_rpm}

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

# Installing Elasticsearch
yum -y install elasticsearch-${elastic_version}
chkconfig --add elasticsearch

# Starting Elasticsearch
service elasticsearch start

# curl https://raw.githubusercontent.com/wazuh/wazuh/3.6/extensions/elasticsearch/wazuh-elastic6-template-alerts.json | curl -XPUT 'http://localhost:9200/_template/wazuh' -H 'Content-Type: application/json' -d @-

#Installing Logstash
yum -y install logstash-${elastic_version}

#Wazuh configuration for Logstash
curl -so /etc/logstash/conf.d/01-wazuh.conf "https://raw.githubusercontent.com/wazuh/wazuh/v${wazuh_version}/extensions/logstash/01-wazuh-remote.conf"

sed -i "s/LS_GROUP=logstash/LS_GROUP=ossec/" /etc/logstash/startup.options

# Configuring jvm.options
cat > /etc/logstash/jvm.options << 'EOF'
-Xms2g
-Xmx2g
-XX:+UseParNewGC
-XX:+UseConcMarkSweepGC
-XX:CMSInitiatingOccupancyFraction=75
-XX:+UseCMSInitiatingOccupancyOnly
-Djava.awt.headless=true
-Dfile.encoding=UTF-8
-Djruby.compile.invokedynamic=true
-Djruby.jit.threshold=0
-XX:+HeapDumpOnOutOfMemoryError
-Djava.security.egd=file:/dev/urandom
EOF

# Configuring RAM memory in jvm.options
ram_gb=$(free -g | awk '/^Mem:/{print $2}')
ram=$(( ${ram_gb} / 4 ))
if [ $ram -eq "0" ]; then ram=1; fi
sed -i "s/-Xms2g/-Xms${ram}g/" /etc/logstash/jvm.options
sed -i "s/-Xmx2g/-Xms${ram}g/" /etc/logstash/jvm.options

# Starting Logstash
initctl start logstash

# Installing Kibana
yum -y install kibana-${elastic_version}
chkconfig --add kibana

# Configuring kibana.yml
cat > /etc/kibana/kibana.yml << EOF
elasticsearch.url: "http://${eth0_ip}:9200"
server.port: ${kibana_port}
server.host: "0.0.0.0"
# server.ssl.enabled: false
# server.ssl.key: /etc/kibana/kibana.key
# server.ssl.certificate: /etc/kibana/kibana.cert
EOF

# Allow Kibana to listen on privileged ports
setcap 'CAP_NET_BIND_SERVICE=+eip' /usr/share/kibana/node/bin/node

export NODE_OPTIONS="--max-old-space-size=3072"

# Installing Wazuh plugin for Kibana
/usr/share/kibana/bin/kibana-plugin install  https://packages.wazuh.com/wazuhapp/wazuhapp-${wazuh_version}_${elastic_version}.zip
cat >> /usr/share/kibana/plugins/wazuh/config.yml << 'EOF'
wazuh.shards: 1
wazuh.replicas: 1
wazuh-version.shards: 1
wazuh-version.replicas: 1
wazuh.monitoring.shards: 1
wazuh.monitoring.replicas: 1
EOF

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

# Starting Kibana
service kibana start

# Disable repositories
sed -i "s/^enabled=1/enabled=0/" /etc/yum.repos.d/elastic.repo
