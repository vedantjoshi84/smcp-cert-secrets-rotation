#!/bin/bash

echo "removing old CA from consul"
CUSTOMER_ID=`consul kv get region_fqdns/$FQDN/customer_uuid`
REGION_ID=`consul kv get region_fqdns/$FQDN/region_uuid`
current_cert_version=`consul kv get customers/$CUSTOMER_ID/regions/$REGION_ID/certs/current_version`
consul kv get customers/$CUSTOMER_ID/regions/$REGION_ID/certs/$current_cert_version/ca/cert > current_ca.$FQDN
#consul kv put customers/$CUSTOMER_ID/regions/$REGION_ID/certs/$current_cert_version/ca/cert.old @current_ca.$FQDN#
consul kv put customers/$CUSTOMER_ID/regions/$REGION_ID/certs/$current_cert_version/ca/cert @new_ca.pem
echo "removed old CA from consul"

echo "latest CA from consul"
consul kv get customers/$CUSTOMER_ID/regions/$REGION_ID/certs/$current_cert_version/ca/cert | openssl x509 -noout -subject -serial -dates
echo "--  old CA revocation process completed for $FQDN --"
