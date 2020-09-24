#include <iostream>
#include <fstream>
#include <string>

const int KEY_SIZE = 4;

/**
 * Convert hex string into int array of specified size.
 */
void hexStrToIntArray(std::string str, unsigned int K[], int arraySize);
void printAsHex(std::pair<unsigned int, unsigned int> data);
void printAsString(std::pair<unsigned int, unsigned int> data);
std::pair <unsigned int, unsigned int> decrypt(unsigned int L, unsigned int R, unsigned int K[KEY_SIZE]);
std::pair <unsigned int, unsigned int> encrypt(unsigned int L, unsigned int R, unsigned int K[KEY_SIZE]);

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

    // split 128-bit key into 4 integers
    unsigned int K[KEY_SIZE];
    hexStrToIntArray(line, K, KEY_SIZE);

    // read in ciphertext
    std::ifstream cipherFile;
    std::string fileName;
    //std::cout << "enter filename to decrypt: ";
    //std::cin >> fileName;
    //fileName = "Practice/practice_ECB-H.crypt";
    fileName = "Ciphertexts/mystery1_ECB-H.crypt";

    cipherFile.open(fileName);
    if (!cipherFile.is_open()) {
        std::cout << "Unable to open cipher file.";
        return 1;
    }

    // for now, assume that ciphertext is also hex.

    std::pair<unsigned int, unsigned int> test = { 0x68696C6C, 0x20796561 };
    printAsString(test);


    while (cipherFile.good()) {
        getline(cipherFile, line);

        for (int i = 0; i < line.length() / 16; i++) {
            unsigned int cipher[2];
            // convert substring to int pair
            hexStrToIntArray(line.substr(i * 16, 16), cipher, 2);
            // decrypt int pair
            auto decryptedPair = decrypt(cipher[0], cipher[1], K);

            printf("original:\t");
            printAsHex({ cipher[0], cipher[1] });

            //unsigned int decrypted[2] = { decryptedPair.first, decryptedPair.second };
            printf("decrypted:\t");
            printAsHex(decryptedPair);

            for (int j = 0; j < 4; j++) {
                char c = (decryptedPair.first >> j * 8);
                std::cout << c << std::endl;
            }
            for (int j = 0; j < 4; j++) {
                char c = (decryptedPair.second >> j * 8);
                std::cout << c << std::endl;
            }

            auto reencryptedPair = encrypt(decryptedPair.first, decryptedPair.second, K);
            printf("re-encrypted:\t");
            printf("%X", reencryptedPair.first);
            printf("%X\n", reencryptedPair.second);
        }
    }
}

void hexStrToIntArray(std::string str, unsigned int K[], int arraySize) {
    for (int i = 0; i < arraySize; i++) {
        std::string substring = str.substr(i * 8, 8);
        K[i] = std::stoul(substring, nullptr, 16);
    }
}

void printAsHex(std::pair<unsigned int, unsigned int> data) {
    printf("%X%X\n", data.first, data.second);
}

void printAsString(std::pair<unsigned int, unsigned int> data) {
    std::string outL = "";
    std::string outR = "";
    // shift chars 8 bits off at a time
    for (int j = 0; j < 4; j++) {
        char c = (data.first >> j * 8) & 0xFF;
        outL = c + outL;
    }
    for (int j = 0; j < 4; j++) {
        char c = (data.second >> j * 8) & 0xFF;
        outR = c + outR;
    }
    std::cout << outL + outR << std::endl;
}

std::pair <unsigned int, unsigned int> decrypt(unsigned int L, unsigned int R, unsigned int K[KEY_SIZE]) {
    unsigned int delta = 0x9e3779b9;
    unsigned int sum = delta << 5;

    for (int i = 0; i < 32; i++) {
        R -= ((L << 4) + K[2]) ^ (L + sum) ^ ((L >> 5) + K[3]);
        L -= ((R << 4) + K[0]) ^ (R + sum) ^ ((R >> 5) + K[1]);
        sum -= delta;
    }

    return std::make_pair(L, R);
}

std::pair <unsigned int, unsigned int> encrypt(unsigned int L, unsigned int R, unsigned int K[KEY_SIZE]) {
    unsigned int delta = 0x9e3779b9;
    unsigned int sum = 0;

    for (int i = 0; i < 32; i++) {
        sum += delta;
        L += ((R << 4) + K[0]) ^ (R + sum) ^ ((R >> 5) + K[1]);
        R += ((L << 4) + K[2]) ^ (L + sum) ^ ((L >> 5) + K[3]);
    }

    return std::make_pair(L, R);
}