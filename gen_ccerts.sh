cp /usr/lib/ssl/openssl.cnf .
chmod 755 ./openssl.cnf
rm -rf demoCA

dir="./demoCA"
certs=$dir/certs
crl_dir=$dir/crl
new_certs_dir=$dir/newcerts
database=$dir/index.txt
serial=$dir/serial

mkdir -p $certs
mkdir -p $crl_dir
mkdir -p $new_certs_dir

touch $database

echo 2000 > $serial

#echo "Generating CA cert"
#openssl req -new -x509 -keyout ca.key -out ca.crt -config openssl.cnf

echo "Generating client csr"
openssl genrsa -aes128 -out client.key 1024
openssl req -new -key client.key -out client.csr -config openssl.cnf

echo "Signing certificate"
openssl ca -in client.csr -out client.crt -cert ca.crt -keyfile ca.key -config openssl.cnf
