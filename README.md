# About

This is an example of how to communicate with an HSM using the [PKCS#11 interface](https://en.wikipedia.org/wiki/PKCS_11).

This uses [opendnssec/SoftHSMv2](https://github.com/opendnssec/SoftHSMv2) as a software-only HSM and [miekg/pkcs11](https://github.com/miekg/pkcs11/) to access the PKCS#11 API of SoftHSM2.

## Usage

Execute the following instructions in a Ubuntu 20.04 terminal.

Install SoftHSM2:

```bash
sudo apt-get install -y softhsm2
```

Kick the tires:

```bash
# configure softhsm to read the configuration from the current directory.
export SOFTHSM2_CONF=$PWD/softhsm2.conf
cat >softhsm2.conf <<'EOF'
# SoftHSM v2 configuration file
  
directories.tokendir = softhsm2-tokens
objectstore.backend = file

# ERROR, WARNING, INFO, DEBUG
log.level = ERROR

# If CKF_REMOVABLE_DEVICE flag should be set
slots.removable = false
EOF
install -d -m 700 softhsm2-tokens
# initialize a token.
# NB so-pin is the Security Office PIN (used to re-initialize the token).
softhsm2-util \
    --init-token \
    --free \
    --label test-token \
    --so-pin 4321 \
    --pin 1234
# generate a key in the normal PKCS#1 format.
openssl genrsa \
    -out test-key.pem \
    2048 \
    2>/dev/null
# convert the key to the PKCS#8 format.
openssl pkcs8 \
    -topk8 \
    -inform pem \
    -in test-key.pem \
    -outform pem \
    -out test-key.pkcs8.pem \
    -nocrypt
# show the key.
openssl rsa \
    -in test-key.pkcs8.pem \
    -text \
    -noout
# import it into the hsm (key must be in the PKCS#8 format).
softhsm2-util \
    --import test-key.pkcs8.pem \
    --token test-token \
    --label test-key \
    --id FFFF \
    --pin 1234
# show the tokens.
softhsm2-util --show-slots
```

Build and execute the example go application:

```bash
# NB this assumes you've already installed go.
#    to install it see https://golang.org/doc/install
go build
# NB use strace -o strace.txt -f ./softhsm2-pkcs11-go-example to troubleshoot the execution.
./softhsm2-pkcs11-go-example
```
