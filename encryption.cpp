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

    return 0;
}
