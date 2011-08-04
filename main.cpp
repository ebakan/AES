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

//convert byte array to hex string
char* byteArrayToHexString(uint8_t* bytes, int len) {
    //for(int i=0;i<len;i++)
        //cout << (int) bytes[i] << " " << (int) bytes[i]/16 << endl;
    char* out=new char[len*2+1];
    char tmp;
    for(int i=0;i<len;i++) {
        //first char
        tmp=bytes[i]/16;
        if(tmp>9)
            tmp+=39;
        out[i*2]=48+tmp;

        //second char
        tmp=bytes[i]%16;
        if(tmp>9)
            tmp+=39;
        out[i*2+1]=48+tmp;
    }
    return out;
}

//convert hex string to byte array
uint8_t* hexStringToByteArray(char* str, int len) {
    uint8_t* out=new uint8_t[len/2];
    for(int i=0;i<len/2;i++) {
        //check if character is valid
        if(str[i*2]<48 || str[i*2]>103 || (str[i*2]>57 && str[i*2]<97)) {
            cerr << "Invalid character "<<str[i+2];
            return NULL;
        }
        if(str[i*2+1]<48 || str[i*2+1]>103 || (str[i*2+1]>57 && str[i*2+1]<97)) {
            cerr << "Invalid character "<<str[i+2+1];
            return NULL;
        }

        //first char
        if(str[i*2]<97)
            out[i]=16*(str[i*2]-48);
        else
            out[i]=16*(str[i*2]-87);
        //second char
        if(str[i*2+1]<97)
            out[i]+=str[i*2+1]-48;
        else
            out[i]+=str[i*2+1]-87;
    }
    return out;
}

int main(int argc, char** argv) {
    //flags and options:
    int bits=0;
    char operation=NULL;
    char* keyFileName=NULL;
    char* inFileName=NULL;
    char* outFileName=NULL;
    ifstream* keyFile=NULL;
    istream* inFile=NULL;
    ostream* outFile=NULL;
    uint8_t* key=NULL;
    char* key_hex=NULL;
    uint8_t* in_block=NULL;

    char help[]= "To use this utility, use the following flags:\n"
                  "-b Key size in bits: 128, 192, 256\n"
                  "    Alternate:\n"
                  "        -bits NUM\n"
                  "        --buts=NUM\n"
                  "-k Key file location\n"
                  "    Alternate:\n"
                  "        -key key File\n"
                  "        --key=KEY (value in hex, no separators, a la \"01020304\")\n"
                  "\n"
                  "Select a mode of operation:\n"
                  "-e Encrypt File\n"
                  "    Alternate:\n"
                  "        -encrypt\n"
                  "-d Decrypt File\n"
                  "    Alternate:\n"
                  "        -decrypt\n"
                  "-c Combined Encrypt and Decrypt File\n"
                  "    Alternate:\n"
                  "        -combined\n"
                  "\n"
                  "-o Output file name (Flag optional, will default to stdout. Will be ignored if -c flag set, in which case program will write out to 'foo'.encrypted and 'foo'.decrypted)\n"
                  "    Alternate:\n"
                  "        -output FILENAME\n"
                  "\n"
                  "Input file handling:\n"
                  "If no input file is selected, the program will default to stdin\n"
                  "Otherwise choose one of the following:\n"
                  "    -i FILE\n"
                  "    -input FILE\n"
                  "    --input=KEY (value in hex, no separators, a la \"01020304\")\n";

    //handle command line arguments
    for(int i=1;i<argc;i++) {
        char* arg=argv[i];

        //got a flag
        if(arg[0]=='-') {

            //got a bit flag
            if(!strcmp(arg,"-b") || !strcmp(arg,"-bits") || !memcmp(arg,"--bits=",7)) {
                if(bits) {
                    cerr << "Can't have more than one key size flag" << endl;
                    return 1;
                }
                if(arg[1]!='-')
                    bits=atoi(argv[++i]);
                else
                    bits=atoi(arg+7);
            }
            
            //got a key flag
            else if(!strcmp(arg,"-k") || !strcmp(arg,"-key") || !memcmp(arg,"--key=",6)) {
                if(keyFileName || key_hex) {
                    cerr << "Can't have more than one key source" << endl;
                    return 1;
                }
                if(arg[1]!='-')
                    keyFileName=argv[++i];
                else
                    key_hex=arg+6;
            }

            //got an operator flag
            else if(!strcmp(arg,"-e")       || !strcmp(arg,"-d")       || !strcmp(arg,"-c") || 
                    !strcmp(arg,"-encrypt") || !strcmp(arg,"-decrypt") || !strcmp(arg,"-combined")) {
                if(operation) {
                    cerr << "Can't have more than one operation flag" << endl;
                    return 1;
                }
                operation=arg[1];
            }

            //got an input flag
            else if(!strcmp(arg,"-i") || !strcmp(arg,"-input") || !memcmp(arg,"--input=",8)) {
                if(inFileName || in_block) {
                    cerr << "Can't have more than one input source" << endl;
                    return 1;
                }
                if(arg[1]!='-')
                    inFileName=argv[++i];
                else {
                    int len=0;
                    while(*(arg+8+len))
                        len++;
                    in_block=hexStringToByteArray(arg+8,len);
                    if(!in_block) {
                        cerr << " in input" << endl;
                        return 0;
                    }
                }
            }

            //got an output flag
            else if(!strcmp(arg,"-o") || !strcmp(arg,"-output")) {
                if(outFileName) {
                    cerr << "Can't have more than one output file" << endl;
                    return 1;
                }
                outFileName=argv[++i];
            }

            //got a help flag
            else if(!strcmp(arg,"-h") || !memcmp(arg,"--help",6)) {
                cout << help;
                return 0;
            }
            
            //got a bad flag
            else {
                cerr << "Invalid flag. Use flag '-h' for help" << endl;
                return 1;
            }
        }

        //got an input file
        else if(!inFileName && !in_block)
            inFileName=arg;

        //bad arg
        else {
            cerr <<"Invalid argument. Can't have more than one input file name" << endl;
            return 1;
        }
    }

    //check arguments
    if(!bits) {
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
    if(!keyFileName && !key_hex) {
        cerr << "No key source selected. Use '-h' for help." << endl;
        return 1;
    }
    if(!inFileName && !in_block) {} //set to cin later
    if(!outFileName) {} //set to cout later
    if(operation=='c' && !inFileName) {
        cerr << "Must have a file name selected with flag '-c'" << endl;
        return 1;
    }

    //set up fstreams
    //if no key passed in
    if(!key_hex) {
        keyFile=new ifstream(keyFileName,ios::binary);
        if(!keyFile->is_open()) { //check if file exists
            cerr << "File " << keyFileName << "does not exist" << endl;
            return 1;
        }
    }

    //handle input file
    if(inFileName) {
        ifstream tmp(inFileName); //check if file exists
        if(!tmp.is_open()) {
            cerr << "File " << inFileName << " does not exist" << endl;
            return 1;
        }
        tmp.close();
        inFile=new ifstream(inFileName,ios::binary);
    }
    else if(!in_block)
        inFile=&cin;
    //if in_key handle later

    //output file
    if(outFileName) 
        outFile=new ofstream(outFileName,ios::binary);
    else if(operation!='c')
        outFile=&cout;

    //get key val
    //if no passed in key, read from file
    if(!key_hex) {
        char* readKey=new char[bits/4];
        keyFile->read(readKey,bits/4);
        key_hex=readKey;
        keyFile->close();
    }

    //check key size
    for(int i=0;i<bits/4;i++) {
        if(!key_hex[i]) {
            cerr << "Invalid key size. Must be 16 bytes for 128-bit encryption, 24 bytes for 192-bit encryption, or 32 bytes for 256-bit encryption" << endl;
            return 1;
        }
    }

    key=hexStringToByteArray(key_hex,bits/4);
    if(!key) {
        cerr << " in key" << endl;
        return 1;
    }



    //actual process

    //set up iv
    uint8_t iv[16];
    if(operation=='e' || operation=='c') {
        srand(time(0));
        for(int i=0;i<16;i++)
            iv[i]=rand()%256;
    }

    //perform operation
    if(inFile) { //dealing with in file stream
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
                ofstream* ofile=new ofstream("AES.cpp.decrypted",ios::binary);
                AES::decryptStream(bits,inFile,ofile,key);

                break;
        }
    }
    else { //dealing with passed in block
        //length of data passed in
        int numBytes=0;
        while(*(in_block+numBytes))
            numBytes++;

        switch(operation) {
            case 'e':
                AES::encrypt(bits,numBytes,iv,in_block,key);

                //set numBytes to final output length
                numBytes+=16; //input array length + iv length
                if(numBytes%16!=0)
                    numBytes+=16-numBytes%16; //pads up to block size
                else
                    numBytes+=16; //else pads another block
                outFile->write(byteArrayToHexString(in_block,numBytes),numBytes*2);
                break;

            case 'd':
                AES::decrypt(bits,numBytes,in_block,key);
                numBytes-=16; //get rid of iv
                numBytes-=in_block[numBytes-1]; //get rid of padding
                break;
        }
    }

    return 0;
}
