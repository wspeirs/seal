# SEAL: **S**imple **E**ncryption and **A**uthentication uti**L**ity

Seal is a very simple utility that will compresses then encrypt for sealing, and the reverse for opening.

There are very few options, as it's meant to be super-simple and straightforward. It leverages zstd for compression, and AEAD (from the ring library) for symetric key encryption/decryption.
