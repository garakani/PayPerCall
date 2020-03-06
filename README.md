# Pay Per Call RPC with Bitcoin/Lightning

This code demonstrates how a server can offer a bundle of RPC calls to a client machine in a secure manner and get paid for it in bitcoins via Bitcoin/Lightning network. The demo code serves as a stub for future applications. Typical extensions of this demo may use it to provide a service by the server, transfer a digital asset from a server to a client, or transfer ownership of one or more assets.

This demo runs on the bitcoin "mainnet" and requires two Ubuntu machines (client and server) running "clightning" implementation of lightning daemon. The server machine should be a bitcoin Full Node running "bitcoind" and "lightingd". The client machine can be a Light Node, which only runs the "lightningd" and utilizes the "bitcoind" on the server.

Prior to running this demo, a lightning payment channel must be established from client to sever and funded on the client side with a small fraction of bitcoins. This makes incoming funds available for client to make payments to server.

The code can be compiled using ubuntu/gcc by running:
make -f Makefile.req

This generates two executable files:
  - reqClient: This is the client executable
  - reqServer: This is the server

To compile the code requires a number of libraries to be installed on the development machine. The required libraries are listed in "Makefile.req".

# Running the demo

On server machine, go to directory containing "reqServer" executable and type:
>    ./reqServer
    
On client machine, go to the directory containing "reqClient" executable and type:
>    ./reqClient ipaddr service quantity
Where
> ipaddr is the IP address of the server machine
> service is a string identifying the service requested (e.g., "quotes" for stock quotes)
> quantity> is an integer specifying the quantity of the service requested (i.e., number of RPC calls that are being requested and paid for by the client machine)

Example: ./reqClient 192.168.3.35 quotes 4

# Secure Communications Using OpenSSL
Client-server communications to request service and exchange payment info and security parameters are secured using OpenSSL (encryption and authentication and signature using RSA public key algorithm with 4096-bit keys).

Securing server and client communications using public key cryptography protects against replay attacks and man-in-the-middle attacks.

Furthermore, the payload of RPC service response can optionally be protected through symmetric encryption (e.g., AES-256), if desired. To support this a random "Session Key" is generated by the server and communicated to the client during initial setup exchange encrypted by the client's public key. Although, demo includes code to generate and exchange "Session Key" for symmetric encryption of the payload, it does not include example code to encrypt payload using symmetric encryption should payload privacy be a requirement.

To make sure RPC requests to services come from authorized clients that have paid for these services, the client generates an initial "Authorization" token and communicates this to the server encrypted by the server's public key. The Authorization token is used by the client machine to generate a set of one time Authorization codes on each subsequent RPC service calls; the one time Authorization codes are verified by the server to make sure the received client requests originate from the authorised client machine that paid for the requested services. The one time Authorization codes are derived from the initial Authorization token and additionally include a sequence number and a random salt.

# RSA Keys

The client generates a new pair of public/private RSA keys, every time the client is invoked. The client is identified through its public RSA key. The client's private/public key pair is stored in memory on client machine. The client's public key is communicated to the server during initial PPC setup exchange.

The server stores its public and private keys in the ".PPC" sub-directory under the home directory on server as follows:
- "key.pri": This file contains the server's private/public key pair.
- "server_pub.pem": This file contains the server's public key, which must be shared with the client.

Client must know server's RSA public key. To share server's public key with the client, the server's public key in "server_pub.pem" file must be copied from the server's ".PPC" subdirectory to the client's ".PPC" subdirectory.  This is for demo purposes. For production code, the client can be informed of the server's public key using either a secure channel out of band or the server's X.509 certificate with a signature chain mapped to a known certificate authority root.

The first time the server comes up, it does not yet have a public/private key pair files.  To generate the key pair on server:
- Make any client service request. Since client does not yet have a valid public key for the server, it would makes its request using a dummy (client generated) public key for the server, which would be rejected by the server, but nonetheless result in generating an initial keypair on the server, which stores it in "key.pri" and "server_pub.pem" in server's ".PPC" subdirectory.
- Distribute the "server_pub.pem" file to the client machine's ".PPC" subdirectory, so subsequent client requests can use the correct server public key.

To regenerate a new server RSA key pairs at any other time:
- bring down server (e.g., ^C),
- delete "key.pri" file from the ".ppc" directory on server.
- Make any client service request. The client would make this request using an invalid public key for the server. Client request would be rejected by the server, but nonetheless result in server to generate a new keypair, which stores it in "key.pri" and "server_pub.pem" in server's ".PPC" subdirectory.
- Distribute the new "server_pub.pem" file to the client machine's ".PPC" subdirectory.
