#include "crypto_context.h"

CryptoContext<DCRTPoly> SetupCKKSContext() {
    CCParams<CryptoContextCKKSRNS> params;
    params.SetMultiplicativeDepth(4);
    params.SetScalingModSize(50);
    params.SetRingDim(16384); // Large enough for batching
    params.SetSecurityLevel(HEStd_128_classic);

    auto cc = GenCryptoContext(params);
    cc->Enable(PKESchemeFeature::PKE);
    cc->Enable(PKESchemeFeature::KEYSWITCH);
    cc->Enable(PKESchemeFeature::LEVELEDSHE);

    return cc;
}
