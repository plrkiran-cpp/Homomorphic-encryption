#include <iostream>
#include <vector>
#include "openfhe.h"

using namespace std;
using namespace lbcrypto;

int main() {
    string scheme_choice;
    int dataset_type;

    // User selects dataset type
    cout << "Select Dataset Type: \n1. Floating-point Threat Scores \n2. Integer-based Threat Counts\n";
    cin >> dataset_type;

    // Automatic scheme selection
    if (dataset_type == 1) {
        scheme_choice = "CKKS";
    } else if (dataset_type == 2) {
        scheme_choice = "BGV";
    } else {
        cout << "Invalid selection. Defaulting to CKKS." << endl;
        scheme_choice = "CKKS";
    }

    cout << "Selected Encryption Scheme: " << scheme_choice << endl;

    // Initialize CryptoContext
    CryptoContext<DCRTPoly> cc;
    if (scheme_choice == "CKKS") {
        CCParams<CryptoContextCKKSRNS> parameters;
        parameters.SetMultiplicativeDepth(6);
        parameters.SetScalingModSize(50);
        parameters.SetBatchSize(8192);
        parameters.SetRingDim(32768);  // 🔥 FIX: Set ring dimension to 32768
        cc = GenCryptoContext(parameters);
    } else {
        CCParams<CryptoContextBGVRNS> parameters;
        parameters.SetMultiplicativeDepth(6);
        parameters.SetPlaintextModulus(65537);
        parameters.SetRingDim(16384);  // 🔥 No change for BGV
        cc = GenCryptoContext(parameters);
    }

    cc->Enable(PKE);
    cc->Enable(KEYSWITCH);
    cc->Enable(LEVELEDSHE);

    cout << "Homomorphic encryption setup completed with scheme: " << scheme_choice << endl;
    return 0;
}
