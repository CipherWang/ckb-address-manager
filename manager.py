# -*- coding: UTF-8 -*-
from bip_utils import Bip39ChecksumError, Bip39Languages, Bip39MnemonicValidator
from bip_utils import Bip39SeedGenerator
from bip_utils.bip.bip44_base import Bip32

from address import generateShortAddress, CODE_INDEX_SECP256K1_SINGLE, ckbhash
from hashlib import sha256

# load mnemonic & generate seed bytes
mnemonic = "comfort rough close flame uniform chapter unique announce miracle debris space like"
seed_bytes = Bip39SeedGenerator(mnemonic).Generate()

# generate HD root key, ckb path is m/44'/309'/0'/change_or_not/child
bip32_ctx = Bip32.FromSeed(seed_bytes)
bip32_ctx = bip32_ctx.DerivePath("44'/309'/0'/0")

# get childkey at specific location
child_id_uint32 = 220342
child_key = bip32_ctx.ChildKey(child_id_uint32)
sk = child_key.PrivateKey().Raw().ToHex()
pk = child_key.PublicKey().RawCompressed().ToHex()

# generate address
blake160_args = ckbhash(bytes.fromhex(pk))[:40]
address = generateShortAddress(CODE_INDEX_SECP256K1_SINGLE, blake160_args, 'mainnet')
print("Sub Key at %d is:\nPrivatekey = %s\nAddress = %s" % (child_id_uint32, sk, address))