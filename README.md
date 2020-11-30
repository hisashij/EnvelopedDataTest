# EnvelopedDataTest

## Contents

- EnvelopedDataTest.c
- EnvelopedDataTest.exe
- testcert.cer
- testcert.der
- testcert.key
- source.txt

## Description

`EnvelopedDataTest` is a command line sample tool which encodes
PKCS#7 enveloped data from the source file and the recepient certificate
 (X.509 DER format).

`Usage: EnvelopedDataTest <source file> <enveloped data file> <recipient cert>`

This program uses wolfSSL v4.5.0.
It have to be linked with wolfSSL static library.

## Testing with sample data

You can test this tool with the sample data as follows.

`> EnvelopedDataTest source.txt result.p7m testcert.der`

Then, you can decode the result data as follows with openssl command.

`> openssl  smime -decrypt -inform DER -in result.p7m -recip testcert.cer -inkey testcert.key`

