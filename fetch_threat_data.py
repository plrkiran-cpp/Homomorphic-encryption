#include "openfhe.h"
#include <iostream>
#include <vector>
#include <chrono>
#include <cmath>
#include <numeric>
#include <random>

using namespace lbcrypto;

// Parameters
const size_t NUM_RECORDS = 1000000;
const size_t CHUNK_SIZE = 8192;  // CKKS constraint: max vector size = ringDim/2

int main() {
    // Start setup timer
    auto t_start = std::chrono::high_resolution_clock::now();

    CCParams<CryptoContextCKKSRNS> parameters;
    parameters.SetMultiplicativeDepth(3);
    parameters.SetScalingModSize(50);
    parameters.SetBatchSize(CHUNK_SIZE);
    parameters.SetRingDim(16384);  // To support bigger vector sizes

    CryptoContext<DCRTPoly> cc = GenCryptoContext(parameters);
    cc->Enable(PKESchemeFeature::ENCRYPTION);
    cc->Enable(PKESchemeFeature::LEVELEDSHE);
    cc->Enable(PKESchemeFeature::SHE);

    auto keys = cc->KeyGen();
    cc->EvalMultKeyGen(keys.secretKey);

    auto t_setup = std::chrono::high_resolution_clock::now();

    // Simulated threat severity data (0.0 to 1.0)
    std::vector<double> severityData(NUM_RECORDS);
    std::default_random_engine eng;
    std::uniform_real_distribution<double> dist(0.5, 1.0);
    for (auto& val : severityData) val = dist(eng);

    auto t_data = std::chrono::high_resolution_clock::now();

    // Encrypt in chunks due to ring dimension limit
    std::cout << "Encrypting in chunks of " << CHUNK_SIZE << "...\n";
    std::vector<Ciphertext<DCRTPoly>> encryptedChunks;

    auto t_encrypt_start = std::chrono::high_resolution_clock::now();

    for (size_t i = 0; i < severityData.size(); i += CHUNK_SIZE) {
        size_t end = std::min(i + CHUNK_SIZE, severityData.size());
        std::vector<double> chunk(severityData.begin() + i, severityData.begin() + end);

        auto pt = cc->MakeCKKSPackedPlaintext(chunk);
        auto ct = cc->Encrypt(keys.publicKey, pt);
        encryptedChunks.push_back(ct);
    }

    auto t_encrypt_end = std::chrono::high_resolution_clock::now();

    // Aggregate encrypted chunks into one ciphertext representing total sum
    std::cout << "Aggregating encrypted chunks...\n";
    Ciphertext<DCRTPoly> encryptedSum = encryptedChunks[0];
    for (size_t i = 1; i < encryptedChunks.size(); ++i) {
        encryptedSum = cc->EvalAdd(encryptedSum, encryptedChunks[i]);
    }

    // Divide by N (homomorphic average)
    double invN = 1.0 / static_cast<double>(NUM_RECORDS);
    auto scalar = cc->MakeCKKSPackedPlaintext(std::vector<std::complex<double>>{invN});
    auto encryptedMean = cc->EvalMult(encryptedSum, scalar);

    auto t_compute = std::chrono::high_resolution_clock::now();

    // Decrypt and print the result
    Plaintext decryptedMean;
    cc->Decrypt(keys.secretKey, encryptedMean, &decryptedMean);
    decryptedMean->SetLength(1);

    std::cout << "Decrypted Mean Severity: " << decryptedMean->GetCKKSPackedValue()[0] << "\n";

    auto t_end = std::chrono::high_resolution_clock::now();

    // Benchmark output
    std::cout << "Encryption time: " << std::chrono::duration<double>(t_encrypt_end - t_encrypt_start).count() << " s\n";
    std::cout << "Setup time: " << std::chrono::duration<double>(t_setup - t_start).count() << " s\n";
    std::cout << "Computastion time (sum + mean): " << std::chrono::duration<double>(t_compute - t_encrypt_end).count() << " s\n";
    std::cout << "Total time: " << std::chrono::duration<double>(t_end - t_start).count() << " s\n";

    return 0;
}
