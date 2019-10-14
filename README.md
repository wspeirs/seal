# SEAL: **S**imple **E**ncryption and **A**uthentication uti**L**ity

Seal is a very simple utility that compresses then encrypts input fed via STDIN. There are very few options, as it's meant to be super-simple and straightforward. It leverages GZip (from the libflate library) for compression, and AEAD (from the ring library) for symetric key encryption/decryption.
