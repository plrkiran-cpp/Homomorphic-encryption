<<<<<<< HEAD
#include "openfhe.h"
#include <iostream>
#include <vector>
#include <chrono>
#include <cmath>

using namespace lbcrypto;

int main() {
    CCParams<CryptoContextCKKSRNS> params;
    params.SetMultiplicativeDepth(2);
    params.SetScalingModSize(50);
    params.SetRingDim(16384); // Important for CKKS large inputs

    CryptoContext<DCRTPoly> cc = GenCryptoContext(params);
    cc->Enable(PKESchemeFeature::PKE);
    cc->Enable(PKESchemeFeature::LEVELEDSHE);

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
=======
#include <iostream>
#include <vector>
#include <curl/curl.h>
#include <nlohmann/json.hpp>
#include "openfhe.h"

using namespace lbcrypto;
using json = nlohmann::json;

// Callback function for libcurl
size_t WriteCallback(void* contents, size_t size, size_t nmemb, std::string* output) {
    size_t totalSize = size * nmemb;
    output->append((char*)contents, totalSize);
    return totalSize;
}

// Function to fetch data from API
json fetchDataFromAPI(const std::string& api_url) {
    CURL* curl = curl_easy_init();
    std::string response;

    if (curl) {
        curl_easy_setopt(curl, CURLOPT_URL, api_url.c_str());
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteCallback);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response);
        curl_easy_perform(curl);
        curl_easy_cleanup(curl);
    }
    return json::parse(response);
}

int main() {
    std::string api_url = "http://127.0.0.1:5000/data";

    // Step 1: Fetch Data from Flask API
    json threatData = fetchDataFromAPI(api_url);
    std::cout << "Fetched Threat Data: " << threatData.dump(4) << std::endl;

    // Step 2: Initialize OpenFHE CKKS Context
    CCParams<CryptoContextCKKSRNS> parameters;
    parameters.SetMultiplicativeDepth(4);
    parameters.SetScalingModSize(50);
    parameters.SetRingDim(8192);

    CryptoContext<DCRTPoly> cryptoContext = GenCryptoContext(parameters);

    cryptoContext->Enable(PKE);  // Enable Public Key Encryption
    cryptoContext->Enable(FHE);  // Enable Fully Homomorphic Encryption

    // Step 3: Generate Key Pair
    auto keyPair = cryptoContext->KeyGen();
    cryptoContext->EvalMultKeyGen(keyPair.secretKey);

    // Step 4: Encrypt Threat Data (Severity Scores)
    std::vector<double> severityScores;
    for (const auto& entry : threatData) {
        severityScores.push_back(entry["severity"]);
    }

    Plaintext plaintext = cryptoContext->MakeCKKSPackedPlaintext(severityScores);
    Ciphertext<DCRTPoly> encryptedData = cryptoContext->Encrypt(keyPair.publicKey, plaintext);

    std::cout << "Data Encrypted Successfully!" << std::endl;

    // Step 5: Perform Homomorphic Computations (Compute Average Severity)
    Ciphertext<DCRTPoly> encryptedSum = encryptedData;
    for (size_t i = 1; i < severityScores.size(); i++) {
        encryptedSum = cryptoContext->EvalAdd(encryptedSum, encryptedData);
    }

    std::vector<double> scalingFactor = {1.0 / severityScores.size()};
    Plaintext scalar = cryptoContext->MakeCKKSPackedPlaintext(scalingFactor);
    Ciphertext<DCRTPoly> encryptedMean = cryptoContext->EvalMult(encryptedSum, scalar);

    // Step 6: Decrypt & Display Result
    Plaintext decryptedMean;
    cryptoContext->Decrypt(keyPair.secretKey, encryptedMean, &decryptedMean);
    decryptedMean->SetLength(1);

    std::cout << "Decrypted Mean Severity Score: " << decryptedMean->GetCKKSPackedValue()[0] << std::endl;
>>>>>>> oldrepo/HE

    return 0;
}
