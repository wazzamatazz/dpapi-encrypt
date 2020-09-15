# dpapi-encrypt

A simple utility for encrypting and decrypting values using the Windows DPAPI. Uses [System.CommandLine](https://github.com/dotnet/command-line-api) for command-line parsing.

Usage:

    dpapi-encrypt encrypt --value <VALUE> --scope <CurrentUser|LocalMachine> [--entropy <ENTROPY>]
    dpapi-encrypt decrypt --value <VALUE> [--entropy <ENTROPY>]

The `--entropy` parameter allows you to specify a base64-encoded string containing additional entropy bytes to pass to the `System.Security.Cryptography.ProtectedData` class.
