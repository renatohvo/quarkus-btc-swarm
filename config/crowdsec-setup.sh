#!/bin/bash

# crowdsec-setup.sh
# This script installs CrowdSec collections, parsers, and scenarios

# Install collections
cscli collections install crowdsecurity/linux --force
cscli collections install crowdsecurity/http-cve --force
cscli collections install crowdsecurity/caddy --force
cscli collections install crowdsecurity/nginx --force
cscli collections install crowdsecurity/apache2 --force
cscli collections install crowdsecurity/mysql --force
cscli collections install crowdsecurity/pgsql --force
cscli collections install crowdsecurity/sshd --force
cscli collections install crowdsecurity/naxsi --force
cscli collections install crowdsecurity/wordpress --force
cscli collections install crowdsecurity/modsecurity --force
cscli collections install crowdsecurity/iis --force
cscli collections install crowdsecurity/smb --force
cscli collections install crowdsecurity/iptables --force
cscli collections install crowdsecurity/postfix --force
cscli collections install crowdsecurity/whitelist-good-actors --force

# Install parsers
cscli parsers install crowdsecurity/http-logs --force
cscli parsers install crowdsecurity/syslog-logs --force
cscli parsers install crowdsecurity/dateparse-enrich --force
cscli parsers install crowdsecurity/iis-logs --force

# Install scenarios
cscli scenarios install crowdsecurity/http-bad-user-agent --force
cscli scenarios install crowdsecurity/http-cve-2021-41773 --force
cscli scenarios install crowdsecurity/http-cve-2021-42013 --force
cscli scenarios install crowdsecurity/http-bf-wordpress_bf --force
cscli scenarios install crowdsecurity/http-sqli-probing --force
cscli scenarios install crowdsecurity/http-xss-probing --force
cscli scenarios install crowdsecurity/ssh-bf --force

# Run the CrowdSec entrypoint
exec /entrypoint.sh