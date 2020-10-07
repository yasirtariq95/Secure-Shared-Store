# Secure-Shared-Store

The goal of the project is to implement secure distributed services. A simple Secure Shared Store (3S) service that allows for the storage and retrieval of documents created by multiple users who access the documents at their local machines. In the implementation, the system should consist of one or more 3S client nodes and a single server that stores the documents. 

Users should be able to login to the 3S server through any client by providing their private key. Session tokens would be generated upon successful authentication of the users. They can then check-in, checkout and delete documents as allowed by access control policies defined by the owner of the document

To implement such a distributed system, we will need to make use of certificates to secure the communication between clients and the server, and to authenticate sources of requests. You will need to make use of a Certificate Authority (CA) that generates certificates for users, client nodes and the server. All nodes trust the CA. 