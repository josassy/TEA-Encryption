//#include <winsock2.h>
#include <algorithm>
#include <iostream>
#include <fstream>
#include <sstream>
#include <string>
#include <stdlib.h>

const int KEY_SIZE = 4;
const int IV_SIZE = 2;

void performHexDecrypt(std::ifstream& cipherFile, std::ostream& outFile, unsigned int K[KEY_SIZE], bool encrypt = false);
void performBinaryECBDecrypt(std::ifstream& cipherFile, std::ostream& outFile, unsigned int K[KEY_SIZE], bool encrypt = false);
void performBinaryCBCDecrypt(std::ifstream& cipherFile, std::ostream& outFile, unsigned int K[KEY_SIZE], std::pair<unsigned int, unsigned int> IV, bool encrypt = false);
void performBinaryCTRDecrypt(std::ifstream& cipherFile, std::ostream& outFile, unsigned int K[KEY_SIZE], std::pair<unsigned int, unsigned int> IV, bool encrypt = false);

void hexStrToIntArray(std::string str, unsigned int K[], int arraySize);
std::string toHexString(std::pair<unsigned int, unsigned int> data);
std::string toAsciiString(std::pair<unsigned int, unsigned int> data);
std::string getBaseName(std::string fileName);
unsigned int reverseBits(unsigned int num);

std::pair <unsigned int, unsigned int> decrypt(unsigned int L, unsigned int R, unsigned int K[KEY_SIZE]);
std::pair <unsigned int, unsigned int> encrypt(unsigned int L, unsigned int R, unsigned int K[KEY_SIZE]);

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

    keyFile.open("teacher-H.iv");
    if (keyFile.is_open()) {
        getline(keyFile, line);
    }
    else {
        std::cout << "Unable to open IV file.";
        return 1;
    }
    keyFile.close();

    // split IV into 2 integers
    unsigned int IV[IV_SIZE];
    hexStrToIntArray(line, IV, IV_SIZE);

    // display welcome message
    bool encryptMode = false;
    printf("Welcome to the TEA encryptor/decryptor.\n");
    while (true) {
        printf("Would you like to encrypt or decrypt today? ");
        std::string userInput;
        getline(std::cin, userInput);
        if (toupper(userInput.at(0)) == 'E') {
            encryptMode = true;
            break;
        }
        else if (toupper(userInput.at(0)) == 'D') {
            encryptMode = false;
            break;
        }
        printf("Invalid input. Try again with '(E)ncrypt' or '(D)ecrypt'.\n");
    }

    // read in ciphertext
    std::ifstream cipherFile;
    std::string fileName;
    std::cout << "enter filename to " << (encryptMode ? "encrypt" : "decrypt") << ": ";
    getline(std::cin, fileName);
    //fileName = "Practice/practice_ECB-H.crypt";
    //fileName = "Practice/practice_ECB-S.crypt";
    //fileName = "Ciphertexts/mystery1_ECB-H.crypt";
    //fileName = "Ciphertexts/mystery2_ECB-S.crypt";
    //fileName = "Ciphertexts/mystery3_CBC-S.crypt";
    //fileName = "Ciphertexts/mystery4_CTR-S.crypt";
    //fileName = "Practice/practice_ECB-S.plain";
    //fileName = "mystery3_CBC-S.plain";

    // retrieve cipherFile base name.
    std::string baseName = getBaseName(fileName);

    // choose output file name
    std::string outFileName = baseName + (encryptMode ? ".crypt" : ".plain");
    std::cout << "Select an output filename.\n(To use default " << outFileName << ", hit ENTER): ";
    std::string userFile;
    getline(std::cin, userFile);
    if (userFile != "") {
        outFileName = userFile;
    }
    
    // open outfilestream
    std::ofstream outFile;
    outFile.open(outFileName);
    if (!outFile.is_open()) {
        std::cout << "Unable to open output file.\n";
        return 1;
    }

    // determine what type of file we are working with.

    // hex data
    if (baseName.at(baseName.length() - 1) == 'H') {
        std::cout << "hex file\n";

        cipherFile.open(fileName);
        if (!cipherFile.is_open()) {
            std::cout << "Unable to open cipher file.\n";
            return 1;
        }
        performHexDecrypt(cipherFile, outFile, K);
    }
    // binary data
    else if (baseName.at(baseName.length() - 1) == 'S') {

        cipherFile.open(fileName, std::ios::in | std::ios::binary);
        if (!cipherFile.is_open()) {
            std::cout << "Unable to open cipher file.\n";
            return 1;
        }
        std::cout << "binary file\n";
        
        // determine which type of TEA algorithm to perform
        std::string teaType = baseName.substr(baseName.length() - 5, 3);
        if (teaType == "ECB") {
            performBinaryECBDecrypt(cipherFile, outFile, K, encryptMode);
        }
        else if (teaType == "CBC") {
            performBinaryCBCDecrypt(cipherFile, outFile, K, { IV[0], IV[1] }, encryptMode);
        }
        else if (teaType == "CTR") {
            performBinaryCTRDecrypt(cipherFile, outFile, K, { IV[0], IV[1] }, encryptMode);
        }
        // invalid. don't try to decrypt.
        else {
            std::cout << "Invalid TEA type \"" << baseName << "\". Must be ECB, CBC, or CTR.\n";
            return 1;
        }

    }
    // invalid. don't try to decrypt.
    else {
        std::cout << "Invalid filename \"" << baseName << "\". Must end with 'H' or 'S'.\n";
        return 1;
    }

    // close output file
    outFile.close();
}

void performHexDecrypt(std::ifstream &cipherFile, std::ostream &outFile, unsigned int K[KEY_SIZE], bool encryptMode) {
    std::string line;
    while (cipherFile.good()) {
        getline(cipherFile, line);
        std::string outputLine = "";
        for (int i = 0; i < line.length() / 16; i++) {
            unsigned int cipher[2];
            // convert substring to int pair
            hexStrToIntArray(line.substr(i * 16, 16), cipher, 2);
            // decrypt int pair
            auto decryptedPair = encryptMode ? encrypt(cipher[0], cipher[1], K) : decrypt(cipher[0], cipher[1], K);
            outputLine += toHexString(decryptedPair);
        }
        std::cout << outputLine << std::endl;
        outFile << outputLine << std::endl;
    }
}

void performBinaryECBDecrypt(std::ifstream& cipherFile, std::ostream& outFile, unsigned int K[KEY_SIZE], bool encryptMode) {
    
    std::stringstream ss;
    while (cipherFile.good()) {
        unsigned int L = 0;
        unsigned int R = 0;

        cipherFile.read((char*)&L, sizeof(L));
        cipherFile.read((char*)&R, sizeof(R));

        // if nothing was read, skip decryption
        if (L == 0 || R == 0) continue;

        L = _byteswap_ulong(L);
        R = _byteswap_ulong(R);

        auto decryptedPair = encryptMode ? encrypt(L, R, K) : decrypt(L, R, K);

        ss << toAsciiString(decryptedPair);
    }
    std::cout << ss.str();
    outFile << ss.str();
}

void performBinaryCBCDecrypt(std::ifstream& cipherFile, std::ostream& outFile, unsigned int K[KEY_SIZE], std::pair<unsigned int, unsigned int> IV, bool encryptMode) {
    std::stringstream ss;

    // use initialization vector for first round additive
    auto additive = IV;

    while (cipherFile.good()) {
        unsigned int L = 0;
        unsigned int R = 0;

        cipherFile.read((char*)&L, sizeof(L));
        cipherFile.read((char*)&R, sizeof(R));

        // if nothing was read, skip decryption
        if (L == 0 || R == 0) continue;

        L = _byteswap_ulong(L);
        R = _byteswap_ulong(R);

        std::pair<unsigned int, unsigned int> decryptedPair = { 0, 0 };
        if (encryptMode) {
            decryptedPair = decrypt(L ^ additive.first, R ^ additive.second, K);
        }
        else {
            decryptedPair = decrypt(L, R, K);

            // apply the additive
            decryptedPair.first = decryptedPair.first ^ additive.first;
            decryptedPair.second = decryptedPair.second ^ additive.second;
        }

        // update the additive
        additive.first = L;
        additive.second = R;

        ss << toAsciiString(decryptedPair);
    }
    std::cout << ss.str();
    outFile << ss.str();
}

void performBinaryCTRDecrypt(std::ifstream& cipherFile, std::ostream& outFile, unsigned int K[KEY_SIZE], std::pair<unsigned int, unsigned int> IV, bool encryptMode) {
    std::stringstream ss;

    // use initialization vector for first round additive
    auto additive = IV;

    // use 64-bit number for incrementing additive
    uint64_t additiveCounter = additive.first;
    additiveCounter = (additiveCounter << 32) ^ additive.second;

    while (cipherFile.good()) {
        unsigned int L = 0;
        unsigned int R = 0;

        cipherFile.read((char*)&L, sizeof(L));
        cipherFile.read((char*)&R, sizeof(R));

        // if nothing was read, skip decryption
        if (L == 0 || R == 0) continue;

        L = _byteswap_ulong(L);
        R = _byteswap_ulong(R);

        auto decryptedPair = encrypt(additive.first, additive.second, K);

        // apply the additive
        decryptedPair.first = decryptedPair.first ^ L;
        decryptedPair.second = decryptedPair.second ^ R;

        // update the additive
        additiveCounter++;
        additive.first = (additiveCounter >> 32) & 0xFFFFFFFF;
        additive.second = additiveCounter & 0xFFFFFFFF;

        ss << toAsciiString(decryptedPair);
    }
    std::cout << ss.str();
    outFile << ss.str();
}

void hexStrToIntArray(std::string str, unsigned int K[], int arraySize) {
    for (int i = 0; i < arraySize; i++) {
        std::string substring = str.substr(i * 8, 8);
        K[i] = std::stoul(substring, nullptr, 16);
    }
}

std::string toHexString(std::pair<unsigned int, unsigned int> data) {
    std::stringstream ss;
    ss << std::hex << data.first << data.second;
    return ss.str();
}

std::string toAsciiString(std::pair<unsigned int, unsigned int> data) {
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
    return outL + outR;
}

std::string getBaseName(std::string fileName) {
    // Find last occurrence of backslash.
    size_t lastSlashIndex = fileName.rfind("/");
    size_t lastBackSlashIndex = fileName.rfind("\\");
    if (std::string::npos == lastSlashIndex) {
        lastSlashIndex = 0;
    }
    else lastSlashIndex++;
    if (std::string::npos == lastBackSlashIndex) {
        lastBackSlashIndex = 0;
    }
    else lastBackSlashIndex++;

    // Find last occurrence of period.
    size_t lastPeriodIndex = fileName.rfind('.');
    if (std::string::npos == lastPeriodIndex)
    {
        lastPeriodIndex = fileName.length();
    }

    // return substring between backslash and period.
    return fileName.substr(lastSlashIndex, lastPeriodIndex - std::max(lastSlashIndex, lastBackSlashIndex));
}

unsigned int reverseBits(unsigned int num) {
    unsigned int  NO_OF_BITS = sizeof(num) * 8;
    unsigned int reverse_num = 0, i, temp;

    for (i = 0; i < NO_OF_BITS; i++)
    {
        temp = (num & (1 << i));
        if (temp)
            reverse_num |= (1 << ((NO_OF_BITS - 1) - i));
    }

    return reverse_num;
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