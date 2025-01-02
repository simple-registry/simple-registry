#!/bin/bash

set -euxo pipefail

SERVER_CA_SUBJECT="/C=US/ST=CA/L=San Francisco/O=My Company/CN=Server CA"
SERVER_SUBJECT="/C=US/ST=CA/L=San Francisco/O=My Company/CN=example.com"

SERVER_CA_CERTIFICATE_FILE=ca-certificate.pem
SERVER_CA_PRIVATE_KEY_FILE=ca-private-key.pem
SERVER_CSR_FILE=x-server-certificate.csr
SERVER_CERTIFICATE_BUNDLE=server-ca-bundle.pem
SERVER_CERTIFICATE_FILE=server-certificate.pem
SERVER_PRIVATE_KEY_FILE=server-private-key.pem

CLIENT_CA_SUBJECT="/C=US/ST=CA/L=San Franciscos/O=My Company/CN=Client CA"
CLIENT_SUBJECT="/C=US/ST=CA/L=San Francisco/O=admins/CN=philippe"

CLIENT_CA_CERTIFICATE_FILE=client-ca-certificate.pem
CLIENT_CA_PRIVATE_KEY_FILE=client-ca-private-key.pem
CLIENT_CSR_FILE=client-certificate.csr
CLIENT_CERTIFICATE_FILE=client-certificate.pem
CLIENT_PRIVATE_KEY_FILE=client-private-key.pem

openssl req -new -x509 -days 365 -nodes \
  -out "$SERVER_CA_CERTIFICATE_FILE" \
  -keyout "$SERVER_CA_PRIVATE_KEY_FILE" \
  -subj "$SERVER_CA_SUBJECT"

openssl req -new -nodes \
  -out "$SERVER_CSR_FILE" \
  -keyout "$SERVER_PRIVATE_KEY_FILE" \
  -subj "$SERVER_SUBJECT" \
  -addext "subjectAltName = IP:192.168.178.135"

openssl x509 -req -in "$SERVER_CSR_FILE" -days 365 -CA "$SERVER_CA_CERTIFICATE_FILE" \
  -CAkey "$SERVER_CA_PRIVATE_KEY_FILE" \
  -CAcreateserial \
  -out "$SERVER_CERTIFICATE_FILE"

cat "$SERVER_CERTIFICATE_FILE" \
    "$SERVER_CA_CERTIFICATE_FILE" > "$SERVER_CERTIFICATE_BUNDLE"

openssl req -new -x509 -days 365 -nodes \
  -out "$CLIENT_CA_CERTIFICATE_FILE" \
  -keyout "$CLIENT_CA_PRIVATE_KEY_FILE" \
  -subj "$CLIENT_CA_SUBJECT"

openssl req -new -nodes \
  -out "$CLIENT_CSR_FILE" \
  -keyout "$CLIENT_PRIVATE_KEY_FILE" \
  -subj "$CLIENT_SUBJECT"

openssl x509 -req -in "$CLIENT_CSR_FILE" -days 365 \
  -CA "$CLIENT_CA_CERTIFICATE_FILE" \
  -CAkey "$CLIENT_CA_PRIVATE_KEY_FILE" \
  -CAcreateserial \
  -out "$CLIENT_CERTIFICATE_FILE"
