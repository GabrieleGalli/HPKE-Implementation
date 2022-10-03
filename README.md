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

[]:
