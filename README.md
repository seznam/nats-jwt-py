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
| `Code`          |  ℹ️   | In this library there is [snippets.py](./jwt_py/jwt/v2/snippets.py) that is targeting to make creation of accounts and users easier.     |
| `Tests`         |  ⚠️   | Tests not covering all code.                                                                                                             |
| `Documentation` |  ℹ️   | NATS has powerful [documentation for JWT](https://docs.nats.io/running-a-nats-service/nats_admin/security/jwt). Recommended for reading. |

## Contributing
`TODOs` are in the code :)  
Please use typing for code you write.

## LICENSE
This library is licensed under the same LICENSE as the [NATS's go library](https://github.com/nats-io/jwt)

## Hint from an Author
When you create an account JWT, you should push it to the server.
It is done by publishing as sys-account to a special subject a JWT
token.
This code can't be part of this library because otherwise it will download extra `nats-py` library.
So here is a snippet for this:
```python
from nats.aio.client import Client as NATS
import nkeys
import base64

async def push_account(
        url: str,
        jwt: str,
        # auth for server by creds
        sys_account_creds: str = None,
        # or by jwt and seed
        sys_account_jwt: str = None,
        sys_account_seed: str = None,
) -> None:
    nats = NATS()
    await nats.connect(
        servers=[url],
        user_credentials=sys_account_creds,
        signature_cb=lambda nonce: base64.b64encode(
            nkeys.from_seed(sys_account_seed.encode()).sign(nonce.encode())
        ),
        user_jwt_cb=lambda: sys_account_jwt.encode(),
    )
    await nats.publish("$SYS.REQ.CLAIMS.UPDATE", jwt.encode())
```
