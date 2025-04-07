#include "openfhe.h"
#include <iostream>
#include <vector>
#include <chrono>
#include <cmath>

using namespace lbcrypto;

int main() {
    // Set encryption parameters
    CCParams<CryptoContextCKKSRNS> params;
    params.SetMultiplicativeDepth(2);
    params.SetScalingModSize(50);
    params.SetRingDim(16384); // Important for CKKS large inputs

    CryptoContext<DCRTPoly> cc = GenCryptoContext(params);
    cc->Enable(PKESchemeFeature::PKE);
    cc->Enable(PKESchemeFeature::LEVELEDSHE);

    // Generate keys
    auto keyPair = cc->KeyGen();
    cc->EvalMultKeyGen(keyPair.secretKey);

    size_t NUM_RECORDS = 1000000;
    std::vector<double> severityScores(NUM_RECORDS);
    for (size_t i = 0; i < NUM_RECORDS; i++) {
        severityScores[i] = 0.5 + 0.4 * sin(i);  // Simulated threat severity pattern
    }

    size_t chunkSize = cc->GetRingDimension() / 2;
    size_t numChunks = (NUM_RECORDS + chunkSize - 1) / chunkSize;

    std::vector<Ciphertext<DCRTPoly>> encryptedChunks;

    std::cout << "Encrypting in chunks of " << chunkSize << "...\n";
    auto encStart = std::chrono::high_resolution_clock::now();

    for (size_t i = 0; i < numChunks; ++i) {
        size_t start = i * chunkSize;
        size_t end = std::min(start + chunkSize, NUM_RECORDS);

        std::vector<std::complex<double>> chunkData;
        for (size_t j = start; j < end; ++j) {
            chunkData.emplace_back(severityScores[j], 0);
        }

        Plaintext pt = cc->MakeCKKSPackedPlaintext(chunkData);
        Ciphertext<DCRTPoly> ct = cc->Encrypt(keyPair.publicKey, pt);
        encryptedChunks.push_back(ct);
    }

    auto encEnd = std::chrono::high_resolution_clock::now();
    std::cout << "Encryption time: "
              << std::chrono::duration<double>(encEnd - encStart).count()
              << " s\n";

    // Aggregate all chunks
    std::cout << "Aggregating encrypted chunks...\n";
    auto totalCT = encryptedChunks[0];
    for (size_t i = 1; i < encryptedChunks.size(); ++i) {
        totalCT = cc->EvalAdd(totalCT, encryptedChunks[i]);
    }

    double invN = 1.0 / NUM_RECORDS;
    Plaintext scalar = cc->MakeCKKSPackedPlaintext(std::vector<std::complex<double>>{invN});
    auto encryptedMean = cc->EvalMult(totalCT, scalar);

    Plaintext decryptedMean;
    cc->Decrypt(keyPair.secretKey, encryptedMean, &decryptedMean);
    decryptedMean->SetLength(1);

    std::cout << "Decrypted Mean Severity: " << decryptedMean->GetCKKSPackedValue()[0] << std::endl;

    return 0;
}
