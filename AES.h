/* AES Encryption
   by Eric Bakan
   12/12/10
*/
#include <stdint.h>
#include <iostream>

#ifndef AES_H
#define AES_H

/*AES Rijndael implementation
  provides encrypt and decrypt methods for 128-bit, 192-bit, and 256-bit encryption
  successfully passes NIST's AES Known Answer Test
  uses PKCS#5 Padding 
*/
class AES {
    private:
        //Lookup Tables
        static const uint8_t rcon       [255];  //Rijndael Rcon operation
        static const uint8_t sbox       [256];  //Rijndael S-Box
        static const uint8_t inv_sbox   [256];  //Rijndael inverse S-box
        static const uint8_t mult_2     [256];  //Rijndael multiplication by 2
        static const uint8_t mult_3     [256];  //Rijndael multiplication by 3
        static const uint8_t mult_9     [256];  //Rijndael multiplication by 9
        static const uint8_t mult_11    [256];  //Rijndael multiplication by 11
        static const uint8_t mult_13    [256];  //Rijndael multiplication by 13
        static const uint8_t mult_14    [256];  //Rijndael multiplication by 14

        //Helper Functions
        static void     rotate          (uint8_t* word);                //Rotates 4-byte array n steps to the left
        static void     scheduleCore    (uint8_t* word, int r);         //Core function of Rjindael's Key Schedule
        
        //Core Processes
        static uint8_t* expandKey       (int keySize, uint8_t* key);    //Expands key into appropriate length for encryption level
        static void     addRoundKey     (uint8_t* state, uint8_t* key); //XORs each byte of the state with its corresponding byte in the round key
        static void     subBytes        (uint8_t* state);               //Substitutes each byte with its corresponding byte in the S-Box
        static void     shiftRows       (uint8_t* state);               //Shifts each row to the left corresponding to its row number
        static void     mixColumns      (uint8_t* state);               //Multiplies each column by the MixColumns matrix

        //Decrypt Processes
        static void     inv_subBytes    (uint8_t* state);               //Substitutes each byte with its corresponding byte in the inverse S-Box
        static void     inv_shiftRows   (uint8_t* state);               //Shifts each row to the right corresponding to its row number
        static void     inv_mixColumns  (uint8_t* state);               //Multiplies each column by the inverse MixColumns matrix

        //Main Functions
        static void encryptBlock        (int keySize, uint8_t* state, uint8_t* key); //Encrypts one 16-byte array of data
        static void decryptBlock        (int keySize, uint8_t* state, uint8_t* key); //Decrypts one 16-byte array of data

    //Encrypt/Decrypt Functions
    public:
       static void encrypt              (int keySize, uint64_t numBytes, uint8_t* iv, uint8_t*& data, uint8_t* key); //Encrypts plaintext with AES cipher
       static void decrypt              (int keySize, uint64_t numBytes, uint8_t*& data, uint8_t* key); //Decrypts cipher with AES cipher
       static void encryptStream        (int keySize, uint8_t* iv, std::istream* in, std::ostream* out, uint8_t* key); //Encrypts stream with AES cipher
       static void decryptStream        (int keySize, std::istream* in, std::ostream* out, uint8_t* key); //Decrypts stream with AES cipher

};
#endif
