#include "crypto_context.h"
#include <iostream>
#include <vector>
#include <chrono>

using namespace lbcrypto;

int main() {
    auto cc = SetupCKKSContext();
    auto keyPair = cc->KeyGen();
    cc->EvalMultKeyGen(keyPair.secretKey);

    const size_t chunkSize = 8192;
    const size_t totalPoints = 1000000;

    std::vector<Ciphertext<DCRTPoly>> encryptedChunks;

    for (size_t i = 0; i < totalPoints; i += chunkSize) {
        std::vector<double> values;
        for (size_t j = 0; j < chunkSize && i + j < totalPoints; ++j)
            values.push_back((i + j) % 1000 / 1000.0); // Example normalized value

        Plaintext pt = cc->MakeCKKSPackedPlaintext(values);
        auto ct = cc->Encrypt(keyPair.publicKey, pt);
        encryptedChunks.push_back(ct);
    }

    std::vector<double> centroids = {0.2, 0.7};  // Two centroids for simplicity
    std::vector<int> clusterAssignments;

    for (const auto& chunk : encryptedChunks) {
        for (const auto& centroid : centroids) {
            Plaintext ptCentroid = cc->MakeCKKSPackedPlaintext(std::vector<double>(chunkSize, centroid));
            auto diff = cc->EvalSub(chunk, ptCentroid);
            auto sqr = cc->EvalMult(diff, diff);

            Plaintext decrypted;
            cc->Decrypt(keyPair.secretKey, sqr, &decrypted);
            decrypted->SetLength(chunkSize);

            double avgDistance = 0.0;
            for (double val : decrypted->GetRealPackedValue())
                avgDistance += val;
            avgDistance /= chunkSize;

            std::cout << "Centroid " << centroid << " avg distance: " << avgDistance << "\n";
        }
    }

    return 0;
}
