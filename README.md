# HPKE-Implementation
What it implements
------------------
The project consists of exchanging encrypted information between a client and a server by making use of the library [HPKE](https://www.rfc-editor.org/rfc/rfc9180.html), which complies with the [HPKE standard](https://www.rfc-editor.org/rfc/rfc9180.html) (RFC 9180).

Steps of the project
------------------
[19-25/09]: study [HPKE](https://www.rfc-editor.org/rfc/rfc9180.html) library + tcp-echo-server.

[27/09]: [HPKE](https://www.rfc-editor.org/rfc/rfc9180.html) library's examples of usage + start the project + exaples of exchange of conditioned data.

[29/09]: created data structures [data_packets_manager](CS-HPKE/client/src/data_packets_manager.rs) for packing + try to exchange some conditioned data between C&S.

[02/10]: exchange of needed data to encrypt and decrypt the message (not working).

[03/10]: exchange of needed data to encrypt and decrypt the message (working) + update data structures (DataPacket, Header) + test functions + organise code.

[07/10]: exchange of ciphersuite and pkR (working on); created [client ciphersuite](CS-HPKE/client/src/ciphersuite_client.rs) [server ciphersuite](CS-HPKE/server/src/ciphersuite_server.rs) in order to manage ciphersuites. Updated [data_packets_manager](CS-HPKE/client/src/data_packets_manager.rs) for new datatypes' options. Updated handle-functions in [client](CS-HPKE/client/src/main.rs) and [server](CS-HPKE/server/src/main.rs).

[08/10]: full exchange of ciphersuite, pkR and text; reorganized code in [client's main](CS-HPKE/client/src/main.rs); TODO: use the new ciphersuite to instatiate kem, kdf, aead.

[12/10]:  found 2 problems: (1): text messages with % and & are not correctly encoded; (2): cannot decide kem, kdf and aead at runtime => use [Agility](https://github.com/rozbb/rust-hpke/blob/master/examples/agility.rs).

[13/10]: study of [Agility](https://github.com/rozbb/rust-hpke/blob/master/examples/agility.rs), its functions and their use.

[Agility-tool branch]

[14/10]: rewrote the code using agility methods => (2) was solved; now [client](https://github.com/GabrieleGalli/HPKE-Implementation/blob/Agility-tool/CS-HPKE/client/src/main.rs) and [server](https://github.com/GabrieleGalli/HPKE-Implementation/blob/Agility-tool/CS-HPKE/server/src/main.rs) exchange algorithms to be used (at runtime) and public key; TODO: decide which MODE to use.
