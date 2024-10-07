openssl req -new -x509 -days 365 -nodes -out ca-certificate.pem -keyout ca-private-key.pem \
  -subj "/C=US/ST=CA/L=San Francisco/O=My Company/CN=Server CA"

openssl req -new -nodes -out server-certificate.csr -keyout server-private-key.pem \
  -subj "/C=US/ST=CA/L=San Francisco/O=My Company/CN=example.com" \
  -addext "subjectAltName = IP:192.168.178.135"
openssl x509 -req -in server-certificate.csr -days 365 -CA ca-certificate.pem -CAkey ca-private-key.pem -CAcreateserial -out server-certificate.pem

cat server-certificate.pem ca-certificate.pem > server-ca-bundle.pem

openssl req -new -x509 -days 365 -nodes -out client-ca-bundle.pem -keyout client-ca-private-key.pem \
  -subj "/C=US/ST=CA/L=San Francisco/O=My Company/CN=example.com"

openssl req -new -nodes -out client-certificate.csr -keyout client-private-key.pem \
  -subj "/C=US/ST=CA/L=San Francisco/O=My Company/CN=example.com"
openssl x509 -req -in client-certificate.csr -days 365 -CA client-ca-bundle.pem -CAkey client-ca-private-key.pem -CAcreateserial -out client-certificate.pem
