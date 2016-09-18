## MiniSS: Mini Secure Sockets

(Read the documentation: https://godoc.org/gopkg.in/bunsim/miniss.v1)

MiniSS is an insanely simple, ridiculously fast, but highly secure secure sockets implementation. It uses triple Diffie-Hellman over Curve25519 elliptic curves to exchange keys, and ChaCha20-Poly1305 to encrypt data within a session. It provides confidentiality and authenticity equivalent to TLS, while providing forward secrecy and deniability at all times. The only dependency is on natrium.

Unlike TLS, MiniSS does not contain any bells and whistles such as heartbeats, session resumption, different choices of ciphers, etc, easing implementation and vastly reducing the attack surface. It is PKI-neutral and does not even contain a certificate mechanism: applications are expected to have their own way of verifying public keys.

MiniSS presents a single interface: `Handshake(...)`, taking in the local end's long-term secret key. Applications should then verify the returned socket for authenticity by means of methods like `RemotePK()`.

All commits on the master branch are cryptographically signed by the PGP key:

````
bunsim <bunsim@protonmail.com>
4096R/4551108DD0CB1E11E9EBF56351B896CAB3EB3B42
````

**Note on security**: One very slight weakening of security of MiniSS compared to TLS is that it does not prevent [truncation attacks](https://en.wikipedia.org/wiki/Transport_Layer_Security#Truncation_attack). However, this is only a concern with application protocols that interpret connection closing as an application-level message, which are highly uncommon nowadays.
