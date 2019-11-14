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


#define CRYPTOPP_ENABLE_NAMESPACE_WEAK 1
#include "cryptopp/md5.h"
#include "cryptopp/cryptlib.h"
#include "cryptopp/hex.h"
#include "cryptopp/modes.h"
#include "cryptopp/osrng.h"
#include "cryptopp/des.h"
#include "cryptopp/base64.h"
#include <cryptopp/hex.h>
#include "cryptopp/rsa.h"
#include <cryptopp/files.h> 
#include <stdio.h> 
#include <sys/socket.h> 
#include <arpa/inet.h> 
#include <unistd.h> 
#include <string.h> 
#include <fstream>

using namespace CryptoPP;   
using namespace std;
void Save(const string& filename, const BufferedTransformation& bt);
void SaveHex(const string& filename, const BufferedTransformation& bt);
void SaveHexPrivateKey(const string& filename, const PrivateKey& key);
void SaveHexPublicKey(const string& filename, const PublicKey& key);
void sendpacket(int new_socket,string message);

string encodedsessionkey,hashencodedsession,encryptedmsg;
string thirdpairkeyfordes;
string messageinputcheckquit;
int socket()
{
    cout<<"Enter Server IP ADDRESS"<<endl;
    string ip;
    cin>>ip;
    int PORT;
    do{
    cout<<"Enter port number"<<endl;
    cin>>PORT;
    if(PORT > 65535 || PORT <1)
    {
	cout<<"are you dumb ? the port range is \"0 - 65535\" "<<endl;
     }
    }while(PORT > 65535 || PORT < 1);
    int sock = 0, valread; 
    struct sockaddr_in serv_addr; 
    if ((sock = socket(AF_INET, SOCK_STREAM, 0)) < 0) 
    { 
        printf("\n Socket creation error \n"); 
	exit(0);
        return -1; 
    } 
   
    serv_addr.sin_family = AF_INET; 
    serv_addr.sin_port = htons(PORT); 
       
    // Convert IPv4 and IPv6 addresses from text to binary form 
    if(inet_pton(AF_INET, ip.c_str(), &serv_addr.sin_addr)<=0)  
    { 
        printf("\nInvalid address/ Address not supported \n"); 
	exit(0);
        return -1; 
    } 
   
    if (connect(sock, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0) 
    { 
        printf("\nConnection Failed \n"); 
	exit(0);
        return -1; 
    }
 	return sock;	
}

void verify(string a, string b)
{

int result = strcmp(a.c_str(), b.c_str());
cout<<"Verifying integrity of file"<<endl;
if(result==0)
{
        cout<<BOLD(FRED("Matched"))<<endl;
}
else
{
	cout<<a<<endl;
	cout<<b<<endl;
        cout<<BOLD(FRED("NOT MATCH!"))<<endl;
        exit(0);
}
}

void keyGen()
{
	AutoSeededRandomPool rng;
	InvertibleRSAFunction privkey;
	privkey.Initialize(rng, 1024);
	/*//Keys create
	Base64Encoder privkeysink(new FileSink("assignment4privatekey.txt"));
	privkey.DEREncode(privkeysink);
	privkeysink.MessageEnd();
	RSAFunction pubkey(privkey);
	Base64Encoder pubkeysink(new FileSink("assignment4publickey.txt"));
	pubkey.DEREncode(pubkeysink);
	pubkeysink.MessageEnd();
*/
    // Generate Private Key
    RSA::PrivateKey privateKey;
    privateKey.GenerateRandomWithKeySize(rng, 1024);
    // Generate Public Key
    RSA::PublicKey publicKey;
    publicKey.AssignFrom(privateKey);
    SaveHexPublicKey("assignment4publickey.txt", publicKey);
    SaveHexPrivateKey("assignment4privatekey.txt", privateKey);
}

void Print(const std::string& label, const std::string& val)
{
   std::string encoded;
   StringSource(val, true,
      new HexEncoder(
         new StringSink(encoded)
      ) // HexEncoder
   ); // StringSource
   std::cout << label << ": " << encoded << std::endl;
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

string grabprivatekey(string filename)
{
 string inputdata,totaldata;
 ifstream file (filename);
  if (file.is_open())
  {
	getline (file,inputdata);
	    file.close();
        return inputdata;
  }
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



//code from stackoverflow
//https://stackoverflow.com/questions/29050575/how-would-i-load-a-private-public-key-from-a-string-byte-array-or-any-other
void Save(const string& filename, const BufferedTransformation& bt)
{
    FileSink file(filename.c_str());
    bt.CopyTo(file);
    file.MessageEnd();
}

void SaveHex(const string& filename, const BufferedTransformation& bt)
{
    HexEncoder encoder;
    bt.CopyTo(encoder);
    encoder.MessageEnd();
    Save(filename, encoder);
}

void SaveHexPrivateKey(const string& filename, const PrivateKey& key)
{
    ByteQueue queue;
    key.Save(queue);
    SaveHex(filename, queue);
}


void SaveHexPublicKey(const string& filename, const PublicKey& key)
{
    ByteQueue queue;
    key.Save(queue);
    SaveHex(filename, queue);
}

string firstkey,secondkey,thirdkey;

void DecryptSession(string session,string privKey)
{
string decodedEncHexEnSeshKey;
StringSource ss(session,true,new HexDecoder(new StringSink(decodedEncHexEnSeshKey)));


AutoSeededRandomPool rng;
InvertibleRSAFunction parameters;
parameters.GenerateRandomWithKeySize(rng,1024);

RSA::PrivateKey privateKey(parameters);
string decodedPrivKey;


StringSource ss2(privKey,true,(new HexDecoder( new StringSink(decodedPrivKey)))); 	//decode the privkey from hex to symbol stuff
StringSource PrivKeySS(decodedPrivKey,true);		//load it into bytes
privateKey.Load(PrivKeySS);		//load the private key 


RSAES_OAEP_SHA_Decryptor d(privateKey);
string hexEnSeshkey;
StringSource ss3(session ,true,(new HexDecoder (new PK_DecryptorFilter(rng, d, (new StringSink(hexEnSeshkey))))));
cout<<"------------------------------------------------Decryption is in progress .. .. .. . . .-------------------------------------"<<endl;
cout<<BOLD(FRED("[ *Session Key found* ] "));
cout<<hexEnSeshkey<<" | MD5 : "<<md5string(hexEnSeshkey)<<endl;
cout<<"------------------------------------------------Process of decryption is completed---------------------------------------"<<endl;

firstkey=hexEnSeshkey;
thirdpairkeyfordes=hexEnSeshkey;
encodedsessionkey=hexEnSeshkey;
	 string  tmp;
        string reverse_sessionkey;
        for(int i=0; i <= encodedsessionkey.length();i++)
        {
                tmp[i]=encodedsessionkey[encodedsessionkey.length()-i];
                 reverse_sessionkey= reverse_sessionkey+tmp[i];
        }
        cout<<"Reverse Endode SessionKey is Ks2 : "<<reverse_sessionkey<<endl;;
secondkey=reverse_sessionkey;

}

string send_recv(int socket, string message, string comments)
{
int valread;
char buffer[1024] = {0};
send(socket , message.c_str() , strlen(message.c_str())+1 , 0 );
cout<<"[ Successfully send to Server ] "<<comments<<endl;
cout<<"Waiting/Receiving Message ... "<<endl;
valread = read(socket , buffer, 1024); 
cout<<"[ Msg from Server ] --> [ Client ] : ";
printf("%s\n",buffer ); 
hashencodedsession=buffer;
encryptedmsg=buffer;
return buffer;
}


void tripleDES_encrypt(string keys,int sock)
{
AutoSeededRandomPool prng;
	string decodedkey;
     StringSource s(keys, true,(new HexDecoder(
		new StringSink(decodedkey))
       ) // StreamTransformationFilter
      ); // StringSource

SecByteBlock key((const byte*)decodedkey.data(), decodedkey.size());

const byte iv[] = {0x12,0x34,0x56,0x78,0x90,0xab,0xcd,0xef};


string plain;
string cipher, encoded, recovered;

/*********************************\
\*********************************/
do
{
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
encryptedmsg=send_recv(sock, encoded, "Encrypted Message in HEXA format");

}

string send_rev_ency_3des(int new_socket, string message, string comments)
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



void tripledes_decrypttext(int socket,string keys,string encryptedmessage)
{
	AutoSeededRandomPool prng;
        string rawcipher,decodedkey;
	StringSource ss2(encryptedmessage, true,
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
	sendpacket(socket,encryptedmessage);
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

void sendpacket(int new_socket,string message)
{
        send(new_socket , message.c_str() , strlen(message.c_str())+1 , 0 ); 
}


int main()
{
    int sock=socket(),valread;
    char buffer[1024] = {0}; 
//    string recieve="Packets received from Client ";
	string recieve="Received Winked From Client";
    cout<<FRED(BOLD("[System] RSA Key is generating"))<<endl;
    keyGen();
    string privatekey=grabprivatekey("assignment4privatekey.txt");
    string publickey=grabfilecontent("assignment4publickey.txt");
    send_recv(sock, publickey, "Public Key have sent");


    cout<<FRED(BOLD("------------------------------------------------PUBLIC KEY AND HASH THAT SEND OVER NETWORK-------------------------------------------------------------------"))<<endl;
    cout<<FRED(BOLD("Value of Public Key"))<<endl;
    cout<<publickey<<endl;
    string publicmd5=md5string(grabfilecontent("assignment4publickey.txt"));
    cout<<FRED(BOLD("[MD5]PUBLIC KEY : "));
    cout<<publicmd5<<endl;

    send_recv(sock, publicmd5, "Hash value \"MD5\" of public key sent");    
    cout<<FRED(BOLD("------------------------------------------------E O F-------------------------------------------------------------------"))<<endl;

    cout<<FRED(BOLD("------------------------------------------------RECEIVED ENCRYPTED SESSION USING PUBLIC KEY AND IT HASH VALUE FROM SERVER-------------------------------------------------------------------"))<<endl;

    string encryptedsession=send_recv(sock, recieve, "Encrypted Session Key from Server"); // received encrypted session key from server
    send_recv(sock, recieve, "Hash value \"MD5\" of Session Key "); // received hash session key from server

    cout<<FRED(BOLD("------------------------------------------------EOF-------------------------------------------------------------------"))<<endl;


    DecryptSession(encryptedsession,privatekey);
    verify(md5string(encodedsessionkey),hashencodedsession);
    string sakeofreturn;
    cout<<FRED(BOLD("3DES KEY IS "));
    cout<<"\""<<firstkey<<secondkey<<"\""<<endl;
    cout<<FRED(BOLD("HANDSHAKE ESTABLISHED\n\n-------------------------------------------------------------------------------------------------"))<<endl;
    string tripledeskey=firstkey+secondkey;
   bool loop=true;
    cin.ignore();
    do
    {
    tripleDES_encrypt(tripledeskey,sock);
    tripledes_decrypttext(sock,tripledeskey,encryptedmsg);
    }while(loop==true);
}
