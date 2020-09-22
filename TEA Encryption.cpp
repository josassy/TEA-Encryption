#include <iostream>
#include <fstream>
#include <string>

const int KEY_SIZE = 4;
int main()
{
    std::ifstream cipherFile;
    std::string fileName;
    std::cout << "enter filename to decrypt: ";
    std::cin >> fileName;

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
    for (int i = 0; i < KEY_SIZE; i++) {
        std::string substring = line.substr(i * 8, 8);
        K[i] = std::stoul(substring, nullptr, 16);
     
        // test to see if integer was read in correctly:
        //printf("\n%X", K[i]);
    }

    // read in ciphertext
    cipherFile.open(fileName);
        
}

std::string decrypt(int L, int R, unsigned int K[KEY_SIZE]) {
    return "";
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

