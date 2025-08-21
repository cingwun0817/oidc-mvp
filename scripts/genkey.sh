#!/usr/bin/env bash
set -e
openssl genrsa -out op_rsa.pem 2048
openssl rsa -in op_rsa.pem -pubout -out op_rsa.pub
echo "Generated op_rsa.pem / op_rsa.pub"