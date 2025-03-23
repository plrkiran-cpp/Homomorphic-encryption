#include <chrono>
#include "openfhe.h"

using namespace lbcrypto;
using namespace std::chrono;

void BenchmarkExecution(const std::string& operation, high_resolution_clock::time_point start) {
    auto end = high_resolution_clock::now();
    auto duration = duration_cast<microseconds>(end - start).count();
    std::cout << operation << " Execution Time: " << duration << " microseconds." << std::endl;
}

int main() {
    CryptoContext<DCRTPoly> cc = InitializeEncryption();
    KeyPair<DCRTPoly> keyPair = cc->KeyGen();
    
    json threat_data = FetchThreatData();

    auto start_encrypt = high_resolution_clock::now();
    vector<Ciphertext<DCRTPoly>> encrypted_data = EncryptThreatData(cc, keyPair, threat_data);
    BenchmarkExecution("Encryption", start_encrypt);

    auto start_cluster = high_resolution_clock::now();
    vector<Ciphertext<DCRTPoly>> clustered_data = HomomorphicKMeans(cc, encrypted_data, 3, 5);
    BenchmarkExecution("Clustering", start_cluster);

    auto start_decrypt = high_resolution_clock::now();
    for (const auto& cipher : clustered_data) {
        Plaintext plaintext;
        cc->Decrypt(keyPair.secretKey, cipher, &plaintext);
        std::cout << "Decrypted Cluster Label: " << plaintext << std::endl;
    }
    BenchmarkExecution("Decryption", start_decrypt);

    return 0;
}
