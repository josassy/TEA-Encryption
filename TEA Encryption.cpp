#include <iostream>
#include <fstream>
#include <string>

const int KEY_SIZE = 4;
int main()
{
    std::ifstream keyFile;
    std::string line;
    keyFile.open("teacher-H.key");
    if (keyFile.is_open()) {
        getline(keyFile, line);
    }
    else {
        std::cout << "Unable to open key file.";
        return 1;
    }
    keyFile.close();
    std::cout << line;

    // split 128-bit key into 4 integers
    unsigned int K[KEY_SIZE];
    hexStrToIntArray(line, K, KEY_SIZE);

    // read in ciphertext
    std::ifstream cipherFile;
    std::string fileName;
    std::cout << "enter filename to decrypt: ";
    std::cin >> fileName;

    cipherFile.open(fileName);
    if (!cipherFile.is_open()) {
        std::cout << "Unable to open cipher file.";
        return 1;
    }

    // for now, assume that ciphertext is also hex.
    while (cipherFile.good()) {
        getline(cipherFile, line);

        for (int i = 0; i < line.length() / 8; i++) {
            unsigned int CIPHER[2];
            // convert substring to int pair
            hexStrToIntArray(line.substr(i * 8, 16), CIPHER, 2);
            // decrypt int pair
            auto decryptedPair = decrypt(CIPHER[0], CIPHER[1], K);


        }
    }



}

/**
 * Convert hex string into int array of specified size.
 */
void hexStrToIntArray(std::string str, unsigned int K[], int arraySize) {
    for (int i = 0; i < arraySize; i++) {
        std::string substring = str.substr(i * 8, 8);
        K[i] = std::stoul(substring, nullptr, 16);
    }
}

std::pair <int, int> decrypt(int L, int R, unsigned int K[KEY_SIZE]) {
    int delta = 0x9e3779b9;
    int sum = delta << 5;

    for (int i = 0; i < 32; ++i) {
        R -= ((L << 4) + K[2]) ^ (L + sum) ^ ((L >> 5) + K[3]);
        L -= ((R << 4) + K[0]) ^ (R + sum) ^ ((R >> 5) + K[1]);
        sum -= delta;
    }

    return std::make_pair(L, R);
}

std::pair <int, int> encrypt(int L, int R, unsigned int K[KEY_SIZE]) {
    int delta = 0x9e3779b9;
    int sum = 0;

    for (int i = 0; i < 32; ++i) {
        sum += delta;
        L += ((R << 4) + K[0]) ^ (R + sum) ^ ((R >> 5) + K[1]);
        R += ((L << 4) + K[2]) ^ (L + sum) ^ ((L >> 5) + K[3]);
    }

    return std::make_pair(L, R);
}


/*
Encryption:
Assuming 32 rounds:
(K[0],K[1],K[2],K[3]) = 128 bit key
(L,R) = plaintext (64-bit block)
delta = 0x9e3779b9
sum = 0
for i = 1 to 32     
    sum += delta     
    L += ((R<<4)+K[0])^(R+sum)^((R>>5)+K[1]) 
    R += ((L<<4)+K[2])^(L+sum)^((L>>5)+K[3])
next i
ciphertext = (L,R)
*/


/*
Decryption:
Assuming 32 rounds:
(K[0], K[1], K[2], K[3]) = 128 bit key
(L, R) = ciphertext(64 - bit block)
delta = 0x9e3779b9
sum = delta << 5
for i = 1 to 32
  R -= ((L << 4) + K[2]) ^ (L + sum) ^ ((L >> 5) + K[3])
  L -= ((R << 4) + K[0]) ^ (R + sum) ^ ((R >> 5) + K[1])
  sum -= delta
next i
plaintext = (L, R)
*/