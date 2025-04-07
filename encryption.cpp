#include "openfhe.h"
#include <iostream>
#include <vector>
#include <cmath>
#include <chrono>

using namespace lbcrypto;

int main() {
    // Setup
    CCParams<CryptoContextCKKSRNS> params;
    params.SetMultiplicativeDepth(3);
    params.SetScalingModSize(50);
    params.SetBatchSize(8192); // Ensures we can fit 8192 doubles per ciphertext
    CryptoContext<DCRTPoly> cc = GenCryptoContext(params);

    cc->Enable(PKESchemeFeature::PKE);
    cc->Enable(PKESchemeFeature::KEYSWITCH);
    cc->Enable(PKESchemeFeature::LEVELEDSHE); // Needed for EvalMult
    cc->Enable(PKESchemeFeature::ADVANCEDSHE);

    auto keys = cc->KeyGen();
    cc->EvalMultKeyGen(keys.secretKey);

    // Simulate 1 million threat scores
    size_t NUM_RECORDS = 1000000;
    std::vector<double> severityScores(NUM_RECORDS, 0.75); // Dummy values for now

    std::vector<Ciphertext<DCRTPoly>> encryptedChunks;
    size_t batchSize = cc->GetRingDimension() / 2;

    std::cout << "Encrypting in chunks of " << batchSize << "..." << std::endl;

    auto startEnc = std::chrono::high_resolution_clock::now();

    for (size_t i = 0; i < NUM_RECORDS; i += batchSize) {
        std::vector<double> chunk(
            severityScores.begin() + i,
            severityScores.begin() + std::min(i + batchSize, severityScores.size())
        );

        Plaintext pt = cc->MakeCKKSPackedPlaintext(chunk);
        auto enc = cc->Encrypt(keys.publicKey, pt);
        encryptedChunks.push_back(enc);
    }

    auto endEnc = std::chrono::high_resolution_clock::now();
    std::cout << "Encryption time: "
              << std::chrono::duration<double>(endEnc - startEnc).count() << " s\n";

    // Sum all encrypted chunks
    std::cout << "Aggregating encrypted chunks...\n";
    auto encSum = encryptedChunks[0];
    for (size_t i = 1; i < encryptedChunks.size(); ++i) {
        encSum = cc->EvalAdd(encSum, encryptedChunks[i]);
    }

    // Compute encrypted mean
    double invN = 1.0 / NUM_RECORDS;
    std::vector<double> scaleVec = {invN};
    auto scalar = cc->MakeCKKSPackedPlaintext(scaleVec);
    auto encMean = cc->EvalMult(encSum, scalar);

    // Decrypt result
    Plaintext result;
    cc->Decrypt(keys.secretKey, encMean, &result);
    result->SetLength(1);

    std::cout << "Decrypted Mean Severity: " << result->GetCKKSPackedValue()[0] << std::endl;

    return 0;
}
