#!/usr/bin/env python
# -*- coding: utf-8 -*-

# Taken from https://github.com/openfheorg/openfhe-python/blob/main/examples/pke/advanced-real-numbers.py
# initially

from openfhe import *
import time

BATCH_SIZE = 8

def param_gen():
    parameters = CCParamsCKKSRNS()
    parameters.SetMultiplicativeDepth(5)
    parameters.SetScalingModSize(50)
    parameters.SetBatchSize(BATCH_SIZE)

    cc = GenCryptoContext(parameters)
    cc.Enable(PKESchemeFeature.PKE)
    cc.Enable(PKESchemeFeature.KEYSWITCH)
    cc.Enable(PKESchemeFeature.LEVELEDSHE)
    return cc

def key_gen(cc):
    keys = cc.KeyGen()
    cc.EvalMultKeyGen(keys.secretKey)
    return keys

def trial(cc, keys):
    # Input
    x = [1.0, 1.01, 1.02, 1.03, 1.04, 1.05, 1.06, 1.07]
    ptxt = cc.MakeCKKSPackedPlaintext(x)
    c = cc.Encrypt(keys.publicKey,ptxt)

    # x^2
    c2_depth2 = cc.EvalMult(c, c)
    c2_depth1 = cc.Rescale(c2_depth2)
    # x^4
    c4_depth2 = cc.EvalMult(c2_depth1, c2_depth1)
    c4_depth1 = cc.Rescale(c4_depth2)
    # x^8
    c8_depth2 = cc.EvalMult(c4_depth1, c4_depth1)
    c8_depth1 = cc.Rescale(c8_depth2)
    # x^16
    c16_depth2 = cc.EvalMult(c8_depth1, c8_depth1)
    c16_depth1 = cc.Rescale(c16_depth2)
    # x^9
    c9_depth2 = cc.EvalMult(c8_depth1, c)
    # x^18
    c18_depth2 = cc.EvalMult(c16_depth1, c2_depth1)
    # Final result
    cRes_depth2 = cc.EvalAdd(cc.EvalAdd(c18_depth2, c9_depth2), 1.0)
    cRes_depth1 = cc.Rescale(cRes_depth2)

    result = cc.Decrypt(cRes_depth1,keys.secretKey)
    result.SetLength(BATCH_SIZE)
    return result

if __name__ == "__main__":
    cc = param_gen()
    keys = key_gen(cc)
    res = trial(cc, keys)
    print(res)
