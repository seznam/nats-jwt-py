# NATS jwt lib for python

Python's library for generating JWT tokens for NATS server.

## ⚠️ Warning ⚠️
> This library is not well-tested and is in the development stage.
> 
> The Author(s) is not a developer of the NATS, so may not understand zen of the NATS.

## Notes

|                 | level | description                                                                                                                              |
|-----------------|:-----:|------------------------------------------------------------------------------------------------------------------------------------------|
| `Code`          |  ℹ️   | This library was inspired and based on [official NATS's go library](https://github.com/nats-io/jwt).                                     |
| `Code`          |  ℹ️   | Author tried to save structure of code that `GoLang` version has, but it is not one-to-one due to languages specs.                       |
| `Code`          |  ℹ️   | In this library there is [snippets.py](jwt/v2/snippets.py) that is targeting to make creation of accounts and users easier.              |
| `Tests`         |  ⚠️   | Tests not covering all code.                                                                                                             |
| `Documentation` |  ℹ️   | NATS has powerful [documentation for JWT](https://docs.nats.io/running-a-nats-service/nats_admin/security/jwt). Recommended for reading. |

## LICENSE
This library is licensed under the same LICENSE as the [NATS's go library](https://github.com/nats-io/jwt)
