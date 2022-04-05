#!/bin/bash
#
# Copyright SecureKey Technologies Inc. All Rights Reserved.
#
# SPDX-License-Identifier: Apache-2.0
#

base58_chars=({1..9} {A..H} {J..N} {P..Z} {a..k} {m..z})

function base58_encode() {
    bc <<<"ibase=16; n=${1^^}; while(n>0) { n%3A ; n/=3A }" |
    tac |
    while read n; do
      echo -n ${base58_chars[n]}
    done
}

function convert_jwk() {
  local d=$(echo $1 | jq -r '.key[0].d' | basenc --base64url -d)
  local x=$(echo $1 | jq -r '.key[0].x' | basenc --base64url -d)

  echo $(base58_encode $(xxd -p -c 256 -u <(echo -n "$d$x")))
}

# wait for comparator service
while [[ "$(curl -s -o /dev/null -L -w "%{http_code}" \
            --cacert /etc/tls/ec-cacert.pem https://comparator.trustbloc.local:8065/healthcheck)" != "200" ]]; do
  sleep 3
done

# create comparator config
comparatorConfig=$(curl -k -o - -s --header "Content-Type: application/json" \
  --request GET \
  --cacert /etc/tls/ec-cacert.pem https://comparator.trustbloc.local:8065/config)

echo $comparatorConfig

comparatorDID=$(echo $comparatorConfig | jq -r '.did')
comparatorKeyID=$(echo "$comparatorDID#$(echo $comparatorConfig | jq -r '.key[0].kid')")
comparatorPrivateKey=$(convert_jwk $comparatorConfig)

# create vc issuer profile for comparator
vc_issuer_comp=$(curl -k -o - -s -w "RESPONSE_CODE=%{response_code}" --header "Content-Type: application/json" --header "Authorization: Bearer vcs_issuer_rw_token" \
  --request POST \
  --data '{"name":"vc-issuer-gk", "uri":"http://example.com", "signatureType":"Ed25519Signature2018", "did":"'"${comparatorDID}"'","didPrivateKey":"'"${comparatorPrivateKey}"'","didKeyID":"'"${comparatorKeyID}"'","signatureRepresentation":1,"didKeyType":"Ed25519"}' \
  --insecure http://vc-issuer.trustbloc.local:8070/profile)

status=${vc_issuer_comp//*RESPONSE_CODE=/}

if [ "$status" == "201" ] || [ "$status" == "400" ]
then
  echo "profile created"
else
  echo ${vc_issuer_comp//RESPONSE_CODE*/} | jq -r '.errMessage'
  exit 1
fi
