#include <openfhe.h>
#include <curl/curl.h>
#include <iostream>
#include <vector>
#include <nlohmann/json.hpp> // JSON library

using namespace lbcrypto;
using json = nlohmann::json;

// Callback function for handling API response
size_t WriteCallback(void* contents, size_t size, size_t nmemb, std::string* s) {
    size_t totalSize = size * nmemb;
    s->append((char*)contents, totalSize);
    return totalSize;
}

// Function to fetch threat data from the API
std::string FetchThreatData(const std::string& api_url) {
    CURL* curl;
    CURLcode res;
    std::string readBuffer;

    curl = curl_easy_init();
    if(curl) {
        curl_easy_setopt(curl, CURLOPT_URL, api_url.c_str());
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteCallback);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, &readBuffer);
        res = curl_easy_perform(curl);
        curl_easy_cleanup(curl);
    }
    return readBuffer;
}

// Function to encode IP address as a double
double EncodeIPAddress(const std::string& ip_address) {
    unsigned int a, b, c, d;
    sscanf(ip_address.c_str(), "%u.%u.%u.%u", &a, &b, &c, &d);
    return a * 16777216 + b * 65536 + c * 256 + d;
}

// Function to encode attack type as a double
double EncodeAttackType(const std::string& attack_type) {
    if (attack_type == "DDoS") return 0.1;
    if (attack_type == "Malware") return 0.2;
    if (attack_type == "Phishing") return 0.3;
    // Add more mappings as needed
    return 0.0;
}

int main() {
    // Initialize OpenFHE context
    uint32_t multDepth = 3;
    uint32_t scaleModSize = 50;
    uint32_t batchSize = 16;
    CryptoContext<DCRTPoly> cc = CryptoContextFactory<DCRTPoly>::genCryptoContextCKKS(
        multDepth, scaleModSize, batchSize);
    cc->Enable(ENCRYPTION);
    cc->Enable(SHE);

    // Key generation
    auto keys = cc->KeyGen();
    cc->EvalMultKeyGen(keys.secretKey);
    cc->EvalSumKeyGen(keys.secretKey);

    // Fetch threat data from the API
    std::string api_url = "https://api.threatintelligenceplatform.com/v1/threat?apiKey=YOUR_API_KEY";
    std::string response = FetchThreatData(api_url);

    // Parse JSON response
    auto json_data = json::parse(response);

    // Iterate over each threat record
    for (const auto& record : json_data) {
        std::string ip_address = record["ip"];
        std::string attack_type = record["attackType"];
        double severity = record["severity"];
        std::string timestamp = record["timestamp"];

        // Encode attributes
        double encoded_ip = EncodeIPAddress(ip_address);
        double encoded_attack_type = EncodeAttackType(attack_type);
        double encoded_timestamp = std::stod(timestamp); // Assuming timestamp is in a numeric string format

        // Create a vector of encoded attributes
        std::vector<double> threat_data = {encoded_ip, encoded_attack_type, severity, encoded_timestamp};

        // Encrypt the threat data
        Plaintext plaintext = cc->MakeCKKSPackedPlaintext(threat_data);
        auto ciphertext = cc->Encrypt(keys.publicKey, plaintext);

        // (Optional) Decrypt to verify
        Plaintext decrypted;
        cc->Decrypt(keys.secretKey, ciphertext, &decrypted);
        decrypted->SetLength(threat_data.size());
        std::cout << "Decrypted data: ";
        for (const auto& val : decrypted->GetRealPackedValue()) {
            std::cout << val << " ";
        }
        std::cout << std::endl;
    }

    return 0;
}
