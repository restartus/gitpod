#!/bin/sh
# Copyright (c) 2020 TypeFox GmbH. All rights reserved.
# Licensed under the MIT License. See License-MIT.txt in the project root for license information.


set -eu

if [ -z "$BASEDOMAIN" ]; then
    >&2 echo "Error: You need to set the environment variable BASEDOMAIN."
    exit 1
fi


# Fix volume ownerships
[ -d "/var/gitlab/gitaly" ] && chown 1000 /var/gitlab/gitaly
[ -d "/var/gitlab/minio" ] && chown 1000 /var/gitlab/minio
[ -d "/var/gitlab/postgresql" ] && chown 1001 /var/gitlab/postgresql
[ -d "/var/gitlab/redis" ] && chown 1001 /var/gitlab/redis


# Add IP tables rules to access Docker's internal DNS 127.0.0.11 from outside
# based on https://serverfault.com/a/826424

TCP_DNS_ADDR=$(iptables-save | grep DOCKER_OUTPUT | grep tcp | grep -o '127\.0\.0\.11:.*$')
UDP_DNS_ADDR=$(iptables-save | grep DOCKER_OUTPUT | grep udp | grep -o '127\.0\.0\.11:.*$')

iptables -t nat -A PREROUTING -p tcp --dport 53 -j DNAT --to "$TCP_DNS_ADDR"
iptables -t nat -A PREROUTING -p udp --dport 53 -j DNAT --to "$UDP_DNS_ADDR"


# Add this IP to resolv.conf since CoreDNS of k3s uses this file

TMP_FILE=$(mktemp)
sed "/nameserver.*/ a nameserver $(hostname -i | cut -f1 -d' ')" /etc/resolv.conf > "$TMP_FILE"
cp "$TMP_FILE" /etc/resolv.conf
rm "$TMP_FILE"



# prepare GitLab helm installer
GITLAB_HELM_INSTALLER_FILE=/var/lib/rancher/k3s/server/manifests/gitlab-helm-installer.yaml

sed -i "s/\$BASEDOMAIN/$BASEDOMAIN/g" "$GITLAB_HELM_INSTALLER_FILE"

cat << EOF > /insert_oauth_application.sql
INSERT INTO oauth_applications (name, uid, secret, redirect_uri, scopes, created_at, updated_at, owner_id, owner_type)
VALUES (
    'Gitpod',
    '2ce8bfb95d9a1e0ed305427f35e10a6bdd1eef090b1890c68e5f8370782d05ee',
    'a5447d23643f7e71353d9fc3ad1c15464c983c47f6eb2e80dd37de28152de05e',
    'https://gitpod.$BASEDOMAIN/auth/gitlab/callback',
    'api read_user read_repository',
    now(), now(), 1, 'User'
);
EOF

insertoauth () {
    echo "Waiting for GitLab DB migrations ..."
    while [ -z "$(kubectl get pods | grep gitlab-migrations | grep Completed)" ]; do sleep 10; done

    echo "Adding OAuth application to DB ..."
    SQL=$(cat /insert_oauth_application.sql)
    DBPASSWD=$(kubectl get secret gitlab-postgresql-password -o jsonpath='{.data.postgresql-postgres-password}' | base64 --decode)
    kubectl exec -it gitlab-postgresql-0 -- bash -c "PGPASSWORD=$DBPASSWD psql -U postgres -d gitlabhq_production -c \"$SQL\""
    echo "OAuth application added to DB."
}
insertoauth &

installation_completed_hook() {
    while [ -z "$(kubectl get pods --all-namespaces | grep helm-install-gitlab | grep Completed)" ]; do sleep 10; done

    echo "Removing installer manifest ..."
    rm -f /var/lib/rancher/k3s/server/manifests/gitlab-helm-intaller.yaml


    echo "Backup secrets ..."
    mkdir -p /var/gitlab/secrets-backup

    while [ -z "$(kubectl get secrets gitlab-rails-secret | grep Opaque)" ]; do sleep 10; done
    [ -f /var/gitlab/secrets-backup/secrets.yaml ] && cp /var/gitlab/secrets-backup/secrets.yaml /var/gitlab/secrets-backup/secrets_backup.yaml
    printf "secrets.yml: " > /var/gitlab/secrets-backup/secrets.yaml
    kubectl get secrets gitlab-rails-secret -o jsonpath="{.data['secrets\.yml']}" >> /var/gitlab/secrets-backup/secrets.yaml
    
    while [ -z "$(kubectl get secrets gitlab-postgresql-password | grep Opaque)" ]; do sleep 10; done
    [ -f /var/gitlab/secrets-backup/postgresql-passwords.yaml ] && cp /var/gitlab/secrets-backup/postgresql-passwords.yaml /var/gitlab/secrets-backup/postgresql-passwords_backup.yaml
    printf "postgresql-password: " > /var/gitlab/secrets-backup/postgresql-passwords.yaml
    kubectl get secrets gitlab-postgresql-password -o jsonpath="{.data.postgresql-password}" >> /var/gitlab/secrets-backup/postgresql-passwords.yaml
    printf "\npostgresql-postgres-password: " >> /var/gitlab/secrets-backup/postgresql-passwords.yaml
    kubectl get secrets gitlab-postgresql-password -o jsonpath="{.data.postgresql-postgres-password}" >> /var/gitlab/secrets-backup/postgresql-passwords.yaml
}
installation_completed_hook &


# add HTTPS certs secret
FULLCHAIN=$(base64 --wrap=0 < /certs/fullchain.pem)
PRIVKEY=$(base64 --wrap=0 < /certs/privkey.pem)
cat << EOF > /var/lib/rancher/k3s/server/manifests/tls-certs.yaml
apiVersion: v1
kind: Secret
metadata:
  name: tls-certs
type: tls
data:
  cert: $FULLCHAIN
  key: $PRIVKEY
EOF


# add rails secret
if [ -f /var/gitlab/secrets-backup/secrets.yaml ]; then
echo "Restoring gitlab-rails-secret ..."
cat << EOF > /var/lib/rancher/k3s/server/manifests/rails-secrets.yaml
apiVersion: v1
kind: Secret
metadata:
  name: gitlab-rails-secret
  labels:
    app: shared-secrets
type: Opaque
data:
EOF
sed 's/^/  /' /var/gitlab/secrets-backup/secrets.yaml >> /var/lib/rancher/k3s/server/manifests/rails-secrets.yaml
fi


# add postgresql passwords secret
if [ -f /var/gitlab/secrets-backup/postgresql-passwords.yaml ]; then
echo "Restoring gitlab-postgresql-password ..."
cat << EOF > /var/lib/rancher/k3s/server/manifests/postgresql-passwords.yaml
apiVersion: v1
kind: Secret
metadata:
  name: gitlab-postgresql-password
type: Opaque
data:
EOF
sed 's/^/  /' /var/gitlab/secrets-backup/postgresql-passwords.yaml >> /var/lib/rancher/k3s/server/manifests/postgresql-passwords.yaml
fi


# start k3s
/bin/k3s server --disable traefik
