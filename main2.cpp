/* AES Encryption
   by Eric Bakan
   12/12/10
*/

#include "AES.h"
#include <stdint.h>
#include <iostream>
#include <fstream>
#include <time.h>
#include <stdlib.h>

using namespace std;

int main(int argc, char** argv) {
    //flags and options:
    uint16_t bits=0;
    char operation=NULL;
    char* keyFileName=NULL;
    char* inFileName=NULL;
    char* outFileName=NULL;
    ifstream* keyFile;
    istream* inFile;
    ostream* outFile;
    uint8_t* key;

    //handle command line arguments
    for(int i=1;i<argc;i++) {
        char* arg=argv[i];
        if(arg[0]=='-') {
            switch(arg[1]) {
                case 'e':
                case 'd':
                case 'c':
                    operation=arg[1];
                    break;

                case 'b':
                    bits=atoi(argv[++i]);
                    break;

                case 'k':
                    keyFileName=argv[++i];
                    break;

                case 'o':
                    outFileName=argv[++i];
                    break;

                case 'h':
                    cerr << "To use this utility, either pass in a file name or pipe in via stdin the plaintext and use the following flags:" << endl;
                    cerr << "-b Key size in bits: 128, 192, 256" << endl;
                    cerr << "-k Key file location" << endl;
                    cerr << endl; 
                    cerr << "Select a mode of operation:" << endl;
                    cerr << "-e Encrypt File" << endl;
                    cerr << "-d Decrypt File" << endl;
                    cerr << "-c Combined Encrypt and Decrypt File" << endl;
                    cerr << endl;
                    cerr << "-o Output file name (Flag optional, will default to stdout. Will be ignored if -c flag set, in which case program will write out to 'foo'.encrypted and 'foo'.decrypted)" << endl;
                    return 0;
                    break;

                default:
                    cerr << "Invalid flag. Use flag '-h' for help" << endl;
                    return 1;
            }
        }
        else if(inFileName==NULL)
            inFileName=arg;
        else {
            cerr <<"Invalid argument. Can't have more than one input file name" << endl;
            return 1;
        }
    }

    //check arguments
    if(bits==0) {
        cerr <<"No bit size selected. Use '-h' for help." << endl;
        return 1;
    }
    if(bits!=128 && bits!=192 && bits!=256) {
        cerr << "Invalid key size. Key size must be either 128, 192, or 256" << endl;
        return 1;
    }
    if(!operation) {
        cerr << "No operation selected. Use '-h' for help." << endl;
        return 1;
    }
    if(!keyFileName) {
        cerr << "No key file selected. Use '-h' for help." << endl;
        return 1;
    }
    if(!inFileName) {} //set to cin later
    if(!outFileName) {} //set to cout later
    if(operation=='c' && !inFileName) {
        cerr << "Must have a file name selected with flag '-c'" << endl;
        return -1;
    }

    //set up fstreams
    keyFile=new ifstream(keyFileName,ios::binary);
    if(!keyFile->is_open()) { //check if file exists
        cerr << "File " << keyFileName << "does not exist" << endl;
        return 1;
    }
    if(inFileName) {
        ifstream tmp(inFileName); //check if file exists
        if(!tmp.is_open()) {
            cerr << "File " << inFileName << " does not exist" << endl;
            return 1;
        }
        inFile=new ifstream(inFileName,ios::binary);
    }
    else
        inFile=&cin;
    if(outFileName) 
        outFile=new ofstream(outFileName,ios::binary);
    else if(operation!='c')
        outFile=&cout;

    //get key val
    char key_hex[bits/4];
    keyFile->read(key_hex,bits/4);

    //check key size
    for(int i=0;i<bits/4;i++) {
        if(!key_hex[i]) {
            cerr << "Invalid key size. Must be 16 bytes for 128-bit encryption, 24 bytes for 192-bit encryption, or 32 bytes for 256-bit encryption" << endl;
            return 1;
        }
    }

    key=new uint8_t[bits/8];

    //convert hex string to byte array
    for(int i=0;i<bits/8;i++) {
        //check if character is valid
        if(key_hex[i*2]<48 || key_hex[i*2]>103 || (key_hex[i*2]>57 && key_hex[i*2]<97)) {
            cerr << "Invalid character "<<key_hex[i+2] << " in key" << endl;
            return 1;
        }
        if(key_hex[i*2+1]<48 || key_hex[i*2+1]>103 || (key_hex[i*2+1]>57 && key_hex[i*2+1]<97)) {
            cerr << "Invalid character "<<key_hex[i+2+1] << " in key" << endl;
            return 1;
        }

        //first char
        if(key_hex[i*2]<97)
            key[i]=16*(key_hex[i*2]-48);
        else
            key[i]=16*(key_hex[i*2]-87);
        //second char
        if(key_hex[i*2+1]<97)
            key[i]+=key_hex[i*2+1]-48;
        else
            key[i]+=key_hex[i*2+1]-87;
    }

    keyFile->close();

    //actual process

    //set up iv
    uint8_t iv[16];
    if(operation=='e' || operation=='c') {
        srand(time(0));
        for(int i=0;i<16;i++)
            iv[i]=rand()%256;
    }

    //perform operation
    switch(operation) {
        case 'e':
            AES::encryptStream(bits,iv,inFile,outFile,key);
            break;
        case 'd':
            AES::decryptStream(bits,inFile,outFile,key);
            break;
        case 'c':
            //gen out file names
            char outFileName_e[128];
            strcpy(outFileName_e,inFileName);
            strcat(outFileName_e,".encrypted");

            char outFileName_d[128];
            strcpy(outFileName_d,inFileName);
            strcat(outFileName_d,".decrypted");
            
            outFile=new ofstream(outFileName_e,ios::binary);
            AES::encryptStream(bits,iv,inFile,outFile,key);

            delete outFile;
            delete inFile;

            inFile=new ifstream(outFileName_e,ios::binary);
            outFile=new ofstream(outFileName_d,ios::binary);
            AES::decryptStream(bits,inFile,outFile,key);

            break;
    }

    return 0;
}
