////////////INCLUDE COLOUR CODE///////////////////
#ifndef _COLORS_
#define _COLORS_
#define RST  "\x1B[0m"
#define KRED  "\x1B[31m"
#define KGRN  "\x1B[32m"
#define KYEL  "\x1B[33m"
#define KBLU  "\x1B[34m"
#define KMAG  "\x1B[35m"
#define KCYN  "\x1B[36m"
#define KWHT  "\x1B[37m"
#define FRED(x) KRED x RST
#define FGRN(x) KGRN x RST
#define FYEL(x) KYEL x RST
#define FBLU(x) KBLU x RST
#define FMAG(x) KMAG x RST
#define FCYN(x) KCYN x RST
#define FWHT(x) KWHT x RST
#define BOLD(x) "\x1B[1m" x RST
#define UNDL(x) "\x1B[4m" x RST
#endif  /* _COLORS_ */
/////////////END OF INCLUDE COLOR CODE////////////////////


// Server side C/C++ program to demonstrate Socket programming 
#include <unistd.h> 
#include <stdio.h> 
#include <sys/socket.h> 
#include <stdlib.h> 
#include <netinet/in.h> 
#include <string.h> 
#include <iostream>
#include <fstream>
#define CRYPTOPP_ENABLE_NAMESPACE_WEAK 1
#include "cryptopp/md5.h"
#include "cryptopp/des.h"
#include "cryptopp/hex.h"
#include "cryptopp/modes.h"
#include "cryptopp/rsa.h"
#include "cryptopp/osrng.h"
#include <cryptopp/base64.h>
using CryptoPP::Base64Encoder;
using CryptoPP::Base64Decoder;
using namespace CryptoPP;   
using namespace std;
void tripledes_decrypt(int socket,string keys);
string tripleDES_encrypt(string tripledeskey,int sock);
//global variable
string SessionKey_encoded,encryptmsg;
string tripledeskey;
string thirdpairkeyfordes;
int PORT;
int socket()
{
    do{
    cout<<"Enter port number to start the listener"<<endl;
    cin >> PORT;
     if(PORT > 65535 || PORT <1)
    { 
        cout<<"are you dumb ? the port range is \"1 - 65535\" "<<endl;
     }

    }while(PORT > 65535 || PORT < 1);
    printf ("[Server] Listening the port %d successfully.\n", PORT);
    int server_fd, new_socket, valread; 
    struct sockaddr_in address; 
    int opt = 1; 
    int addrlen = sizeof(address); 
       
    // Creating socket file descriptor 
    if ((server_fd = socket(AF_INET, SOCK_STREAM, 0)) == 0) 
    { 
        perror("socket failed"); 
        exit(EXIT_FAILURE); 
    } 
       
    // Forcefully attaching socket to the port 8080 
    if (setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR | SO_REUSEPORT, 
                                                  &opt, sizeof(opt))) 
    { 
        perror("setsockopt"); 
        exit(EXIT_FAILURE); 
    } 
    address.sin_family = AF_INET; 
    address.sin_addr.s_addr = INADDR_ANY; 
    address.sin_port = htons( PORT ); 
       
    // Forcefully attaching socket to the port 8080 
    if (bind(server_fd, (struct sockaddr *)&address,  
                                 sizeof(address))<0) 
    { 
        perror("bind failed"); 
        exit(EXIT_FAILURE); 
    } 
    if (listen(server_fd, 3) < 0) 
    { 
        perror("listen"); 
        exit(EXIT_FAILURE); 
    } 
    if ((new_socket = accept(server_fd, (struct sockaddr *)&address,  
                       (socklen_t*)&addrlen))<0) 
    { 
        perror("accept"); 
        exit(EXIT_FAILURE); 
    } 
	return new_socket ;
}



void SaveContent(string content, string filename)
{
	  ofstream file;
	  file.open (filename);
	  file << content;
	  file.close();
}

string md5string(string haha)
{

#define CRYPTOPP_ENABLE_NAMESPACE_WEAK 1

byte digest[ CryptoPP::Weak::MD5::DIGESTSIZE ];
std::string message = haha;

CryptoPP::Weak::MD5 hash;
hash.CalculateDigest( digest, (const byte*)message.c_str(), message.length() );

CryptoPP::HexEncoder encoder;
std::string output;

encoder.Attach( new CryptoPP::StringSink( output ) );
encoder.Put( digest, sizeof(digest) );
encoder.MessageEnd();

return output;
}


string grabfilecontent(string filename)
{
 string inputdata,totaldata;
 ifstream file (filename);
  if (file.is_open())
  {
int counter=0;
    while(getline (file,inputdata))
     {
                totaldata=totaldata+inputdata+"\n";
     }
    file.close();
        return totaldata;
  }
}

void send_rev_ency_3des(int new_socket, string message, string comments)
{
  
   tripledes_decrypt(new_socket,tripledeskey);
   tripleDES_encrypt(tripledeskey,new_socket);
}


string send_recv(int new_socket, string message, string comments)
{
    int valread;
    char buffer[1024] = {0}; 
	string compare;
        valread = read( new_socket , buffer, 1024); 
	cout<<"[ Msg from Client ] --> [ Server ] : "<<buffer<<endl;
    	send(new_socket , message.c_str() , strlen(message.c_str())+1 , 0 ); 
    	cout<<"[ Details ] "<<comments<<endl;
return buffer;
}

void sendpacket(int new_socket,string message)
{
        send(new_socket , message.c_str() , strlen(message.c_str())+1 , 0 ); 
}


void verify(string a, string b)
{

int result = strcmp(a.c_str(), b.c_str());
cout<<"Verifying integrity of file"<<endl;
if(result==0)
{
	cout<<FRED(BOLD("Matched"))<<endl;
}
else
{
	cout<<FRED(BOLD("File is tampered"))<<endl;
	exit(0);
}
}

string DecryptSessionUsingPriv(string privKey,string session)
{
	//Get private key
	AutoSeededRandomPool rng;
	ByteQueue bytes;
	StringSource pr(privKey, true, new Base64Decoder);
	pr.TransferTo(bytes);
	bytes.MessageEnd();
	RSA::PrivateKey privateKey;
	privateKey.Load(bytes);

	//Decrypt session key
	string session_key, decoded_sessionKey;
	RSAES_OAEP_SHA_Decryptor d(privateKey);

	//convert char array(c style string) to string(c++ string)
	string sessionKey=session;
	StringSource(sessionKey, true, new HexDecoder(new StringSink(decoded_sessionKey)));
	StringSource(decoded_sessionKey, true, new PK_DecryptorFilter(rng, d, new StringSink(session_key)));
	cout<<session_key<<endl;
	//Convert session key to byte
	SecByteBlock sessionKeyToByte;
	sessionKeyToByte = SecByteBlock(reinterpret_cast<const byte *>(session_key.data()), (session_key.size()));
	int keySize;
	keySize = sessionKeyToByte.size();

}

string hashvaluesessionkey,firstkey,secondkey,thirdkey;
string generateSessionKey(int sock,string publickey)
{
	AutoSeededRandomPool prng;
	InvertibleRSAFunction parameters;
	RSA::PublicKey publicKey(parameters);
	parameters.GenerateRandomWithKeySize(prng,1024);
	int keys=8;
	SecByteBlock key(keys);	
	prng.GenerateBlock(key, key.size());

	//Convert key from bytes to string
	string stringKey,temporary;
	ArraySource (key, sizeof(key), true, new StringSink(stringKey));
	string encodestringKey;
	StringSource encodekey(stringKey, true, new HexEncoder(
	new StringSink(temporary)));
	encodestringKey=temporary.substr(0,16);
	cout<<BOLD(FRED("[--------------------------------SESSION KEY IS GENERATING-----------------------------]"))<<endl;
	cout<<"EncodedSessionKey Ks1 : "<<encodestringKey<<endl;
	thirdpairkeyfordes=encodestringKey;
	string  tmp;
	string reverse_sessionkey;

	for(int i=0; i <= encodestringKey.length();i++)
	{
		tmp[i]=encodestringKey[encodestringKey.length()-i];
		 reverse_sessionkey= reverse_sessionkey+tmp[i];
	}
	firstkey=encodestringKey;
	cout<<"Reverse Endode SessionKey is Ks2 : "<<reverse_sessionkey<<endl;;
	secondkey=reverse_sessionkey;
	hashvaluesessionkey=encodestringKey;
	string decodedpubkey;
	StringSource decodekey(publickey,true,new HexDecoder( new StringSink(decodedpubkey)));
	StringSource pubKeySS(decodedpubkey,true);
	publicKey.Load(pubKeySS);

	string encryptedSessionKey;
	RSAES_OAEP_SHA_Encryptor e(publicKey);
	StringSource encryptboth(encodestringKey, true, new PK_EncryptorFilter(prng,e,(new HexEncoder(new StringSink(encryptedSessionKey)))));
	cout<<BOLD(FRED("[--------------------------------SESSION KEY GENERATE COMPLETED-----------------------------]"))<<endl;
	cout<<BOLD(FRED("[--------------------------PERFORM ENCRYPTION ON  SESSION KEY USING PUBLIC KEY -----------------------------]"))<<endl;
	cout<<"[ENCRYPTED]"<<encryptedSessionKey<<endl;
	
	return encryptedSessionKey;
}

string tripleDES_encrypt(string tripledeskey,int sock)
{
	AutoSeededRandomPool prng;
        string decodedkey;
        StringSource s(tripledeskey, true,(new HexDecoder(
                new StringSink(decodedkey))
       ) // StreamTransformationFilter
      ); // StringSource

SecByteBlock key((const byte*)decodedkey.data(), decodedkey.size());

const byte iv[] = {0x12,0x34,0x56,0x78,0x90,0xab,0xcd,0xef};


string plain;
string cipher, encoded, recovered;

/*********************************\
\*********************************/

do{
cout<<"Enter message send to server"<<endl;
std::getline(std::cin, plain);
if(plain.size()>1024)
{
cout<<BOLD(FRED("Message is exceed the length"))<<endl;
}
}while(plain.size()>1024);
try
{

    CBC_Mode< DES_EDE2 >::Encryption e;
    e.SetKeyWithIV(key,key.size(),iv);

    // The StreamTransformationFilter adds padding
    //  as required. ECB and CBC Mode must be padded
    //  to the block size of the cipher.
    StringSource ss1(plain, true, 
        new StreamTransformationFilter(e,
            new StringSink(cipher)
 ) // StreamTransformationFilter      
    ); // StringSource
}
catch(const CryptoPP::Exception& e)
{
    cerr << e.what() << endl;
    exit(1);
}

StringSource ss2(cipher, true,
    new HexEncoder(
        new StringSink(encoded)
    ) // HexEncoder
); // StringSource
cout << "cipher text [ENCODED] : " << encoded << endl;
sendpacket(sock,encoded);
return plain;
}


void tripledes_decrypt(int socket,string keys)
{
    int valread;
    char buffer[1024] = {0}; 
        string compare;
        valread = read( socket , buffer, 1024); 
	cout<<"CipherText [HEX Encoded] : \""<<buffer<<"\""<<endl;
	AutoSeededRandomPool prng;
        string rawcipher,decodedkey;
	StringSource ss2(buffer, true,
    	new HexDecoder(
        	new StringSink(rawcipher)
	    ) // HexEncoder
	); // StringSource

     	StringSource s(keys, true,(new HexDecoder(
        new StringSink(decodedkey))));
	SecByteBlock key((const byte*)decodedkey.data(), decodedkey.size());
	const byte iv[] = {0x12,0x34,0x56,0x78,0x90,0xab,0xcd,0xef};

try
{
    CBC_Mode< DES_EDE2 >::Decryption d;
    d.SetKeyWithIV(key, key.size(), iv);
    string recovered;
    // The StreamTransformationFilter removes
    //  padding as required.
	string decodedmessage;
	string decodeencryptedmessage;


    StringSource ss3(rawcipher, true, 
        new StreamTransformationFilter(d,
            new StringSink(recovered)
        ) // StreamTransformationFilter
    ); // StringSource
    if(recovered=="quit")
     {
        cout<<BOLD(FRED("--------------------------------------\"QUIT\"---------------------------------"))<<endl;
	sendpacket(socket,buffer);
	exit(1);
     }
    cout << "recovered text: " << recovered << endl;
}
catch(const CryptoPP::Exception& e)
{
    cerr << e.what() << endl;
    exit(1);
}
}


int main(int argc, char const *argv[]) 
{ 
   int new_socket=socket(),valread;
   char *hello = "Received Wink > .. < ";
   string dummy="";
   string sakeofreturn;
   string publickey=send_recv(new_socket, hello, "Public key from Client");//send received wink
   SaveContent(publickey,"received_publickey.txt");
   string hashvalue=send_recv(new_socket, hello, "Hash value from Client"); // send received wink
   string contentofpublickeytoverify=grabfilecontent("received_publickey.txt");
   verify(hashvalue,md5string(contentofpublickeytoverify));
   sakeofreturn=generateSessionKey(new_socket,publickey);
   send_recv(new_socket, sakeofreturn, "Server --> Client | Encrypted Session Key");

   string md5sessionencode=md5string(hashvaluesessionkey);
   cout<<BOLD(FRED("[---------------------------------END OF FILE------------------------------------------]\n\n"))<<endl;
   cout<<BOLD(FRED("[--------------------------GENERATING HASH VALUE OF ENCRYPTED SESSION KEY FROM CLIENT -----------------------------]"))<<endl;
   cout<<FRED(BOLD("MD5 of the PUBLICKEY + SESSION KEY : "));
   cout<<"\""<<md5sessionencode<<"\" "<<endl;
   sakeofreturn=send_recv(new_socket, md5sessionencode, "Server --> Client | MD5 Session Key");
   cout<<BOLD(FRED("[---------------------------------END OF FILE------------------------------------------]\n\n"))<<endl;
   cout<<BOLD(FRED("3DES KEY is "));
   cout<<"\""<<firstkey<<secondkey<<"\""<<endl;
   tripledeskey=firstkey+secondkey;
   cout<<BOLD(FRED("HANDSHAKE ESTABLISHED\n\n-------------------------------------------------------------------------------------------------"))<<endl;
   bool loop=true;
   cin.ignore();
   do{
   cout<<"Receiving Message from Client"<<endl;
   send_rev_ency_3des(new_socket, "BD49328613133DFF", "Encrypted Message using 3DES send from Client");//send received wink
   }while(loop==true);
   return 0;
} 
