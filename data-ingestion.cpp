#include <iostream>
#include <curl/curl.h>
#include <nlohmann/json.hpp>
#include "openfhe.h"

using json = nlohmann::json;
using namespace lbcrypto;

size_t WriteCallback(void* contents, size_t size, size_t nmemb, std::string* output) {
    size_t total_size = size * nmemb;
    output->append((char*)contents, total_size);
    return total_size;
}

json FetchThreatData() {
    CURL* curl = curl_easy_init();
    std::string response;

    if (curl) {
        curl_easy_setopt(curl, CURLOPT_URL, "http://127.0.0.1:5000/get_threat_data");
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteCallback);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response);
        curl_easy_perform(curl);
        curl_easy_cleanup(curl);
    }
    return json::parse(response);
}

vector<Ciphertext<DCRTPoly>> EncryptThreatData(
    CryptoContext<DCRTPoly> cc, KeyPair<DCRTPoly> keyPair, json &threat_data) {

    vector<Ciphertext<DCRTPoly>> encrypted_data;
    for (const auto& item : threat_data) {
        double score = item["threat_score"];
        auto plaintext = cc->MakePackedPlaintext({score});
        encrypted_data.push_back(cc->Encrypt(keyPair.publicKey, plaintext));
    }
    return encrypted_data;
}

int main() {
    json threat_data = FetchThreatData();

    CryptoContext<DCRTPoly> cc = InitializeEncryption();
    KeyPair<DCRTPoly> keyPair = cc->KeyGen();
    cc->EvalMultKeyGen(keyPair.secretKey);
    
    vector<Ciphertext<DCRTPoly>> encrypted_data = EncryptThreatData(cc, keyPair, threat_data);
    
    std::cout << "Successfully encrypted " << encrypted_data.size() << " threat scores." << std::endl;
    return 0;
}
