#!/bin/bash

usage() {
    echo "Usage: $(basename "$0") <hostname> [<port>]"
    echo "Example: $(basename "$0") example.com"
    echo "Example: $(basename "$0") example.com 8443"
    exit 1
}

# --- Configuration ---
SERVER_ADDRESS=$1
SERVER_PORT=${2:-443}
OUTPUT_DIR="./certificates"      # Directory to save the certificates
# --------------------

# --- Script Logic ---
if [[ -z "$SERVER_ADDRESS" ]]; then
    usage
fi

# Create output directory if it doesn't exist
mkdir -p "$OUTPUT_DIR"

# Use openssl to connect to the server and retrieve the certificate chain
# -showcerts: Prints the certificates in the chain
# -connect: Connects to the specified address and port
# |: Pipes the output to the next command
# awk: Processes the output line by line
# /-----BEGIN CERTIFICATE-----/,/-----END CERTIFICATE-----/: Matches lines within the certificate boundaries
# count++: Increments the certificate counter
# > "$OUTPUT_DIR/certificate_$count.pem": Redirects the matched lines to a new file
echo | openssl s_client -showcerts -connect "$SERVER_ADDRESS":"$SERVER_PORT" 2>/dev/null | awk '/-----BEGIN CERTIFICATE-----/,/-----END CERTIFICATE-----/{
    if (match($0, /-----BEGIN CERTIFICATE-----/)) {
        count++
        print > "'"$OUTPUT_DIR"'/certificate_"count".pem"
    } else {
        print >> "'"$OUTPUT_DIR"'/certificate_"count".pem"
    }
}'

# Identify and rename the certificates
# The first file should be the server certificate, the others are intermediate and root
# Examine the issuer and subject to differentiate them

# Process each downloaded certificate file
for cert_file in "$OUTPUT_DIR"/certificate_*.pem; do
    # Extract subject and issuer
    subject=$(openssl x509 -noout -subject -in "$cert_file" | sed 's/Subject: CN = \(.*\)/\1/')
    issuer=$(openssl x509 -noout -issuer -in "$cert_file" | sed 's/Issuer: CN = \(.*\)/\1/')

    echo "Processing file: $cert_file"
    echo " Subject Name  : $subject"
    echo "  Issuer Name  : $issuer"

    # Determine certificate type based on subject and issuer
    if [[ "$subject" == "$issuer" ]]; then
        # If subject and issuer are the same, it's likely the root certificate
        mv "$cert_file" "$OUTPUT_DIR/root_certificate.pem"
        echo "Root certificate saved as: root_certificate.pem"
    elif [[ "$subject" == *"$SERVER_ADDRESS"* ]]; then
        # If the subject contains the server address, it's likely the server certificate
        # (This is a simplified check, adjust as needed)
        mv "$cert_file" "$OUTPUT_DIR/server_certificate.pem"
        echo "Server certificate saved as: server_certificate.pem"
    else
        # Otherwise, it's an intermediate certificate
        mv "$cert_file" "$OUTPUT_DIR/intermediate_certificate_$(basename "$cert_file")"
        echo "Intermediate certificate saved as: $(basename "$cert_file")"
    fi
done

echo "Certificate chain download and separation complete."

echo "The root certificate is not provided by the remote server."
echo "You have to download the root certificate from the Certificate Authority"
                                                                                       