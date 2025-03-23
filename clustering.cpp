#include "openfhe.h"
#include <iostream>
#include <vector>

using namespace lbcrypto;
using namespace std;

Ciphertext<DCRTPoly> ComputeSquaredDistance(
    CryptoContext<DCRTPoly> cc,
    Ciphertext<DCRTPoly> encrypted_x,
    Ciphertext<DCRTPoly> centroid) {

    auto diff = cc->EvalSub(encrypted_x, centroid);
    return cc->EvalMult(diff, diff);
}

vector<Ciphertext<DCRTPoly>> InitializeCentroids(
    CryptoContext<DCRTPoly> cc, 
    vector<Ciphertext<DCRTPoly>> &encrypted_data, int k) {

    vector<Ciphertext<DCRTPoly>> centroids;
    auto global_mean = encrypted_data[0];

    for (size_t i = 1; i < encrypted_data.size(); i++) {
        global_mean = cc->EvalAdd(global_mean, encrypted_data[i]);
    }

    auto count_inverse = cc->MakePackedPlaintext({1.0 / encrypted_data.size()});
    global_mean = cc->EvalMult(global_mean, count_inverse);

    for (int i = 0; i < k; i++) {
        auto perturbation = cc->MakePackedPlaintext({(double)i * 0.1});
        centroids.push_back(cc->EvalAdd(global_mean, perturbation));
    }
    return centroids;
}

vector<Ciphertext<DCRTPoly>> HomomorphicKMeans(
    CryptoContext<DCRTPoly> cc, 
    vector<Ciphertext<DCRTPoly>> encrypted_data, int k, int iterations) {

    vector<Ciphertext<DCRTPoly>> centroids = InitializeCentroids(cc, encrypted_data, k);

    for (int iter = 0; iter < iterations; iter++) {
        vector<vector<Ciphertext<DCRTPoly>>> clusters(k);
        
        // Assign points to closest cluster
        for (auto &enc_point : encrypted_data) {
            Ciphertext<DCRTPoly> min_dist = ComputeSquaredDistance(cc, enc_point, centroids[0]);
            int best_cluster = 0;

            for (int j = 1; j < k; j++) {
                Ciphertext<DCRTPoly> dist = ComputeSquaredDistance(cc, enc_point, centroids[j]);
                if (cc->EvalCompare(dist, min_dist)) {
                    min_dist = dist;
                    best_cluster = j;
                }
            }
            clusters[best_cluster].push_back(enc_point);
        }

        for (int j = 0; j < k; j++) {
            if (!clusters[j].empty()) {
                Ciphertext<DCRTPoly> new_centroid = clusters[j][0];
                for (size_t i = 1; i < clusters[j].size(); i++) {
                    new_centroid = cc->EvalAdd(new_centroid, clusters[j][i]);
                }
                auto count_inverse = cc->MakePackedPlaintext({1.0 / clusters[j].size()});
                centroids[j] = cc->EvalMult(new_centroid, count_inverse);
            }
        }
    }
    return centroids;
}
