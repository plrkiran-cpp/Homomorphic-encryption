<<<<<<< HEAD
# Homomorphic-encryption
=======
# Experimentation_HE

Pull openfhe development
integrate these files into openfhe development
run server/python3 app.py
run client
plrkiran@macbookair-1 client % g++ -std=c++17 encryption.cpp -o encryption \
  -I/usr/local/include/openfhe \
  -I/usr/local/include/openfhe/core \
  -I/usr/local/include/openfhe/pke \
  -I/usr/local/include/openfhe/binfhe \
  -I/opt/homebrew/Cellar/nlohmann-json/3.11.3/include \
  -L/usr/local/lib -lOPENFHEcore -lOPENFHEpke -lOPENFHEbinfhe -lcurl \
  -Wl,-rpath,/usr/local/lib

g++ -std=c++17 clustering.cpp -o clustering \
  -I/usr/local/include/openfhe \
  -I/usr/local/include/openfhe/core \
  -I/usr/local/include/openfhe/pke \
  -I/usr/local/include/openfhe/binfhe \
  -I/opt/homebrew/Cellar/nlohmann-json/3.11.3/include \
  -L/usr/local/lib -lOPENFHEcore -lOPENFHEpke -lOPENFHEbinfhe -lcurl \
  -Wl,-rpath,/usr/local/lib

./encryption
./clustering
>>>>>>> oldrepo/HE
