# HPKE-Implementation
What it implements
------------------
The project consists of exchanging encrypted information between a client and a server by making use of the library [HPKE](https://www.rfc-editor.org/rfc/rfc9180.html), which complies with the [HPKE standard](https://www.rfc-editor.org/rfc/rfc9180.html) (RFC 9180). The aim is to demonstrate that [PDMv2](https://datatracker.ietf.org/doc/html/draft-ietf-ippm-encrypted-pdmv2-02) correctly integrates confidentiality, integrity and authentication to PDM. Briefly, from a primary client (PC) and a primary server (PS) performing a lightweight handshake, it must be possible to derive one or more secondary clients (SC) and one or more secondary servers (SS) that communicate in a secure manner.

Steps of the project
------------------
[19-25/09]: study [HPKE](https://www.rfc-editor.org/rfc/rfc9180.html) library + tcp-echo-server.

[27/09]: [HPKE](https://www.rfc-editor.org/rfc/rfc9180.html) library's examples of usage + start the project + exaples of exchange of conditioned data.

[29/09]: created data structures [data_packets_manager](CS-HPKE/client/src/data_packets_manager.rs) for packing + try to exchange some conditioned data between C&S.

[02/10]: exchange of needed data to encrypt and decrypt the message (not working).

[03/10]: exchange of needed data to encrypt and decrypt the message (working) + update data structures (DataPacket, Header) + test functions + organise code.

[07/10]: exchange of ciphersuite and pkR (working on); created [client ciphersuite](CS-HPKE/client/src/ciphersuite_client.rs) [server ciphersuite](CS-HPKE/server/src/ciphersuite_server.rs) in order to manage ciphersuites. Updated [data_packets_manager](CS-HPKE/client/src/data_packets_manager.rs) for new datatypes' options. Updated handle-functions in [client](CS-HPKE/client/src/main.rs) and [server](CS-HPKE/server/src/main.rs).

[08/10]: full exchange of ciphersuite, pkR and text; reorganized code in [client's main](CS-HPKE/client/src/main.rs); TODO: use the new ciphersuite to instatiate kem, kdf, aead.

[12/10]:  found 2 problems: (1 ok): text messages with % and & are not correctly encoded; (2 ok): cannot decide kem, kdf and aead at runtime => use [Agility](https://github.com/rozbb/rust-hpke/blob/master/examples/agility.rs).

[13/10]: study of [Agility](https://github.com/rozbb/rust-hpke/blob/master/examples/agility.rs), its functions and their use.

[Agility-tool branch]

[14/10]: rewrote the code using agility methods => (2) solved; now [client](https://github.com/GabrieleGalli/HPKE-Implementation/blob/Agility-tool/CS-HPKE/client/src/main.rs) and [server](https://github.com/GabrieleGalli/HPKE-Implementation/blob/Agility-tool/CS-HPKE/server/src/main.rs) exchange algorithms to be used (at runtime) and public key; TODO: decide which MODE to use.

[17/10]: TODO: (3 ok) change algorithm code exchange using UTF16 Big Endian (via [from_be_bytes](https://doc.rust-lang.org/std/primitive.u16.html#method.from_be_bytes) and [to_be_bytes](https://doc.rust-lang.org/std/primitive.u16.html#method.to_be_bytes). (4 ok) Use only [AuthPSK MODE](https://www.rfc-editor.org/rfc/rfc9180.html) => DO NOT exchange PSKs (note to both), EXCHANGE PSK_ID (sent INCLUDED) => use map or match {C and S can have multiple PSKs, each is associated with a PSK_ID }. NB, limits for PSK and PSK_ID in [rfc](https://www.rfc-editor.org/rfc/rfc9180.html) - 60 bits may be OK for all algorithms. (5) ENC is associated with SESSION C-S (map).

[18/10]: (3) solved. Now every packet sent has an additional bit that spcifies how to read the packet (UTF8 or UTF16). Added variants of the handle_data function (for u8 and for u16). Updated the way a packet is created.

[21/10]: (4) solved. C and S exchange PSK_IDs and use a common PSK (contained in [psk](https://github.com/GabrieleGalli/HPKE-Implementation/blob/Agility-tool/CS-HPKE/server/src/psk.rs) both C and S) to instantiate their own PskBundle. C generates the ENC and sends it to S. Now, C and S have their own aead context with which they can encrypt and decrypt a message.

[24/10]: (1) solved. Now C and S correctly exchange encrypted messages.

[25/10]: TODO: (6 ok) create Secondary Client SC and Secondary Server SS. SC and SS MUST know each other in advance. 

[26-28/10]: (6) solved. -> Intermediate step <-: SC communicates with PC and gets the necessary data for aead ctx, same thing three SS and PC. SC(SS) sends a hello message to PC(PS) (authentication) and this, if it has finished the first negotiation with PS(PC), sends it the data.
