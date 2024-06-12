#!/bin/bash

set -eo pipefail

FQDN=$1
KUBECONFIG=$2

if [ $# -ne 2 ]; then
  echo "Usage: $0 <FQDN> <KUBECONFIG>"
  exit 1
fi

DU_NS=$(echo "$FQDN" | cut -d'.' -f1)

report_error() {
  echo "## error: Failed to revoke old/previous CA"
}

trap 'report_error' ERR

echo "-- starting previous/old CA revocation process for $FQDN --"
echo "DU FQDN: $FQDN"
echo "DU NS: $DU_NS"

export KUBECONFIG
export CONSUL_HTTP_ADDR="http://decco-consul-consul-ui.default.svc.cluster.local:80"
export CONSUL_HTTP_TOKEN=$(yq r .airctl/state.yaml 'kplaneTokenJson' | jq -r '.SecretID')
NOW=`date +%s`
DIR="$DU_NS-old-ca-removal-$NOW"
mkdir $DIR
pushd $DIR
kubectl -n $DU_NS get secret tcp-cert -oyaml > $DU_NS-tcp-cert-origial.yml
tcp_cert_json=`kubectl -n $DU_NS get secret tcp-cert -ojson`
current_ca_hash=`echo $tcp_cert_json | jq -r '.data."ca.pem"' | base64 -d | openssl x509 -noout -subject_hash`
current_ca_hash_key="$current_ca_hash.0"
echo $tcp_cert_json | jq -r --arg current_ca_hash_key "$current_ca_hash_key" ".data.\"$current_ca_hash_key\"" | base64 -d > current_ca_chain.pem
total_certs_in_ca_chain=$(grep -c "BEGIN CERTIFICATE" "current_ca_chain.pem")
echo "total number of certificates in current_ca_chain: $total_certs_in_ca_chain"
if [ "$total_certs_in_ca_chain" -eq 1 ]; then
  echo "only one certificate in CA chain. probably KDU CA was never rotated.. nothing to do"
  echo "removing dir: $DIR"
  rm -rf $DIR
  exit 0
fi

cat current_ca_chain.pem | awk '/-----BEGIN CERTIFICATE-----/, /-----END CERTIFICATE-----/' | awk '/-----BEGIN CERTIFICATE-----/{i++} i==1' > new_ca.pem
cat current_ca_chain.pem | awk '/-----BEGIN CERTIFICATE-----/, /-----END CERTIFICATE-----/' | awk '/-----BEGIN CERTIFICATE-----/{i++} i==3' > old_ca.pem
old_ca_details=$(openssl x509 -in "old_ca.pem" -noout -subject -serial -dates)

echo "old/previous CA details:"
echo "$old_ca_details"

current_ca_details=$(openssl x509 -in "new_ca.pem" -noout -subject -serial -dates)
echo "current CA details:"
echo "$current_ca_details"

echo "removing old CA from tcp-cert secret in KDU namespace"
new_ca_b64=`cat new_ca.pem | base64 -w0`
echo "{
  \"data\": {
    \"$current_ca_hash_key\": \"$new_ca_b64\",
    \"ca.crt\": \"$new_ca_b64\",
    \"ca.pem\": \"$new_ca_b64\"
  }
}" > new_ca_patch.json

kubectl -n $DU_NS patch secret tcp-cert  --patch "$(cat new_ca_patch.json)" --type merge
echo "restarting pods with socat containers"
deployments_with_socat=$(kubectl get deployments -n ${DU_NS} -o jsonpath='{range .items[*]}{.metadata.name}{" "}{.spec.template.spec.containers[*].name}{"\n"}{end}' | grep -i "socat" | awk '{print $1}' | tr '\n' ' ')
eval kubectl -n ${DU_NS} rollout restart deployment ${deployments_with_socat}

popd
