""" Module testing functionality of `ClaimsData` class.

`ClaimsData` is a base class for all other specific claims classes.

So every claims class should be tested here.
"""
import json
import unittest
from dataclasses import asdict, is_dataclass

from nats_jwt.nkeys_ext import create_operator_pair
from nats_jwt.v2.claims import ClaimsData, safe_url_base64_decode
from nats_jwt.v2.header import AlgorithmNkey, Header, TokenTypeJwt
from nats_jwt.v2.operator_claims import Operator
from nats_jwt.v2.snippets import Operator as OperatorSnippet


class ClaimsDataTestCase(unittest.TestCase):
    def test_claims_initializer(self):
        """ Initializing of claims requires name and subject. """
        # test nothing is passed
        with self.assertRaises(TypeError):
            ClaimsData()

        # test only name is passed
        with self.assertRaises(TypeError):
            ClaimsData(name="test")

        # test only subject is passed
        with self.assertRaises(TypeError):
            ClaimsData(sub="test")

        # test both name and subject are passed
        cd = ClaimsData(name="test_name", sub="test_sub")
        assert cd.name == "test_name"
        assert cd.sub == "test_sub"

    @staticmethod
    def test_claims_can_be_serialized():
        """ Claims can be serialized to JSON. """
        cd = ClaimsData(name="test_name", sub="test_sub")

        # assert for dataclass
        assert is_dataclass(cd)

        cd_dict: dict = asdict(cd)

        # assert for keys in dict
        keys = cd_dict.keys()
        assert "name" in keys
        assert "sub" in keys

        # asdict do not omit empty fields
        for field in {"aud", "exp", "jti", "iat", "iss"}:
            assert field in keys
            assert not cd_dict[field]

        # convert to json
        cd.to_json()  # noqa

    def test_claims_encoding(self):
        """ Claims can be encoded to JSON. """
        cname = "test_name"
        csub = "test_sub"
        cd = ClaimsData(name=cname, sub=csub)

        # test on an operator pair
        key_pair = create_operator_pair()

        # convert to jwt
        with self.assertRaises(AttributeError):
            # we have no NATS attr, so it should raise an exception
            cd.do_encode(
                header=Header(TokenTypeJwt, AlgorithmNkey),
                kp=key_pair,
                claim=cd,
            )

        cd.nats = Operator()

        # now we have claims.nats, so it should not raise an exception
        jwt = cd.do_encode(
            header=Header(TokenTypeJwt, AlgorithmNkey),
            kp=key_pair,
            claim=cd,
        )

        chunks = jwt.split(".")
        assert len(chunks) == 3

        # convert first to chunks to json
        header_json = safe_url_base64_decode(chunks[0].encode())
        payload_json = safe_url_base64_decode(chunks[1].encode())

        # check valid json
        header: dict = json.loads(header_json)
        payload: dict = json.loads(payload_json)

        # check for keys in header
        assert "alg" in header
        assert "typ" in header
        assert header["typ"] == TokenTypeJwt
        assert header["alg"] == AlgorithmNkey

        # check for keys in payload
        assert "name" in payload
        assert "sub" in payload
        assert payload["name"] == cname
        assert payload["sub"] == csub

    @staticmethod
    def test_claim_hash_is_the_same():
        """ Claims hash is the same for the same claims. """
        cd1 = ClaimsData(name="test_name", sub="test_sub")
        cd2 = ClaimsData(name="test_name", sub="test_sub")

        assert cd1.hash() == cd2.hash()

    @staticmethod
    def test_decoding_claims():
        # create operator snippet pair
        o = OperatorSnippet()
        account = o.create_account("unit_test_account")
        jwt = account.jwt
        account_claims_t = account.claims_t

        # try decode claims
        decoded_claims = account_claims_t.decode_claims(jwt)
        assert decoded_claims.name == account.claims.name
        assert decoded_claims.sub == account.claims.sub


if __name__ == '__main__':
    unittest.main()
