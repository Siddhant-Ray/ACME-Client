# NetworkSecurity-ACME-Project

Contains my solution for the ACME project for the course Network Security HS 2021 at ETH Zurich.

To run the ACME client, cd to project and execute 
1. ./compile
2. ./run 

To run the test ACME certificate authority (CA), cd to pebble-test and execute 
1. ./pebble-run.sh 

Before running the project, GO must be installed and added to path. 

Running example : 

### Input and Output
#### File layout
We will supply you with a basic skeleton which you should use for submission. Three files in this skeleton are of particular importance:
- `pebble.minica.pem`
This is the CA certificate for the private key used to sign the certificate of the HTTPS endpoint of the ACME server itself. Use this as a trust root to check the ACME server's certificate when interacting with this endpoint. You will lose points if your application sends more than one request to an ACME server with an invalid certificate (one request is needed to obtain the certificate and check its validity).
- `compile`
This file will be executed by the automated-testing environment before any tests are run. You should modify this file. If your project needs to be compiled, this file should contain the commands needed to compile the project. If no compilation is needed, this file can do nothing (or install dependencies).
- `run`
This file will be executed by the testing environment when the tests are being run. You should modify this file. It will receive the command-line arguments listed below. Your `compile` script may overwrite this file.

Note that all paths in your code should be relative to the root of the repository.

#### Command-line arguments 
Your application should support the following command-line arguments (passed to the `run` file):

**Positional arguments:**
- `Challenge type`
_(required, `{dns01 | http01}`)_ indicates which ACME challenge type the client should perform. Valid options are `dns01` and `http01` for the `dns-01` and `http-01` challenges, respectively.

**Keyword arguments:**
- `--dir DIR_URL`
_(required)_ `DIR_URL` is the directory URL of the ACME server that should be used.
- `--record IPv4_ADDRESS` 
_(required)_ `IPv4_ADDRESS` is the IPv4 address which must be returned by your DNS server for all A-record queries. 
- `--domain DOMAIN`
_(required, multiple)_ `DOMAIN`  is the domain for  which to request the certificate. If multiple `--domain` flags are present, a single certificate for multiple domains should be requested. Wildcard domains have no special flag and are simply denoted by, e.g., `*.example.net`.
- `--revoke`
_(optional)_ If present, your application should immediately revoke the certificate after obtaining it. In both cases, your application should start its HTTPS server and set it up to use the newly obtained certificate.

**Example:**
Consider the following invocation of `run`:
```
run dns01 --dir https://example.com/dir --record 1.2.3.4 --domain netsec.ethz.ch --domain syssec.ethz.ch
```
When invoked like this, your application should obtain a single certificate valid for both `netsec.ethz.ch` and `syssec.ethz.ch`. It should use the ACME server at the URL `https://example.com/dir` and perform the `dns-01` challenge. The DNS server of the application should respond with `1.2.3.4` to all requests for `A` records. Once the certificate has been obtained, your application should start its certificate HTTPS server and install the obtained certificate in this server.
