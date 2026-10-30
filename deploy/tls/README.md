# TLS certificate

Place the certificate chain and key for the upload hostname here:

- `upload.crt`: certificate followed by any intermediate certificates
- `upload.key`: private key, readable by the proxy container (uid 101)

Use your internal CA. For a local test only, `scripts/dev-cert.sh <hostname>`
makes a self-signed pair.
