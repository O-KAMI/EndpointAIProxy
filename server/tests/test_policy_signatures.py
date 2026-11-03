import base64
import importlib.util
import os

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.exceptions import InvalidSignature
from config import ROOT
from controlserver.security import sign_ed25519


def test_signing_config_is_optional_and_invalid_seed_fails(config):
    assert config.POLICY_SIGNING_KEY is None
    config.ED25519_SEED_TEXT = base64.b64encode(bytes(31)).decode()
    with pytest.raises(ValueError, match="Ed25519 seed"):
        config.validate()
    config.ED25519_SEED_TEXT = base64.b64encode(bytes(range(32))).decode()
    config.validate()
    body = b"synthetic policy"
    sig = sign_ed25519(body, config.POLICY_SIGNING_KEY, "policy")
    assert sig == "ed25519-v1:xgsc0hsLjP_MvWXeRW-Hn7qwufu4KcBpSwsqibsFYkbu0WUzmD1D8cNEpPmFILXs5ckRJImW3tGJj1CdO9tADQ"
    raw = base64.urlsafe_b64decode(sig.split(":", 1)[1] + "==")
    with pytest.raises(InvalidSignature):
        config.POLICY_SIGNING_KEY.public_key().verify(raw, b"sf-endpointai-command-ed25519-v1\n" + body)


@pytest.mark.skipif(os.name != "posix", reason="POSIX private directory permissions require a native Linux check")
def test_new_signing_key_directory_is_private_and_never_overwritten(tmp_path):
    spec = importlib.util.spec_from_file_location("create_policy_signing_key", ROOT / "tools/create_policy_signing_key.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    target = tmp_path / "keys"
    module.create(target)
    assert target.stat().st_mode & 0o077 == 0
    private = target / "signing-seed.env"
    public = target / "policy-public-key.txt"
    assert private.stat().st_mode & 0o077 == public.stat().st_mode & 0o077 == 0
    seed = base64.b64decode(private.read_text().split("=", 1)[1], validate=False)
    derived = Ed25519PrivateKey.from_private_bytes(seed).public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    assert base64.b64decode(public.read_text()) == derived
    with pytest.raises(FileExistsError):
        module.create(target)
