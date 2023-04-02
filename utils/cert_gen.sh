#!/bin/bash

# Generate the CA key and cert
openssl req -new -x509 -days 3650 -keyout ca.key -out ca.crt -nodes -subj "/CN=CA"

# Generate the server key and cert
openssl genrsa -out server.key 2048
openssl req -new -key server.key -out server.csr -subj "/CN=Server"
openssl x509 -req -in server.csr -CA ca.crt -CAkey ca.key -CAcreateserial -out server.crt -days 3650

# Generate the client key and cert
openssl genrsa -out client.key 2048
openssl req -new -key client.key -out client.csr -subj "/CN=Client"
openssl x509 -req -in client.csr -CA ca.crt -CAkey ca.key -CAcreateserial -out client.crt -days 3650

# Cleanup
rm server.csr client.csr
