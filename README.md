# dpapi-encrypt

A simple utility for encrypting and decrypting values using the Windows DPAPI. Uses [System.CommandLine](https://github.com/dotnet/command-line-api) for command-line parsing.

Usage:

    dpapi-encrypt encrypt --value <VALUE> --scope <CurrentUser|LocalMachine> [--entropy <ENTROPY>]
    dpapi-encrypt decrypt --value <VALUE> [--entropy <ENTROPY>]
