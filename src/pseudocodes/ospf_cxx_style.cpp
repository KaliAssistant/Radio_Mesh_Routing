/*
 * Author: KaliAssistant
 * Github: https://github.com/KaliAssistant
 * Licence: GNU/GPLv3.0
 *
 */



#define TYPE_L2LAYER_MAGICCODE 0xC65A   // Header Type Magic Code For DataLink header 0xC65A
#define TYPE_HELLOPACKET_MAGICCODE 0x9AB8   // Packet Type Magic Code For HelloPacket 0x9AB8


/*
 *   L2 Header
 *   
 *   +--------------------------- L2 Header ------------------------------+
 *   +    00  01  02  03  04  05  06  07  08  09  0A  0B  0C  0D  0E  0F  +
 *   +--------------------------------------------------------------------+
 *   + 0| .D  .A  .L  C6  5A [--------- 10 Byte L3 CheckSum --------] FF |+
 *   +--------------------------------------------------------------------+
 *   
 *   TOTAL 16 Byte
 */


/*
 *   L3 Packet
 *
 *   +-------------------------- Hello Packet ----------------------------+
 *   +    00  01  02  03  04  05  06  07  08  09  0A  0B  0C  0D  0E  0F  +
 *   +--------------------------------------------------------------------+
 *   + 0| .N  .E  .T  9A  B8 [--------------------- 16 byte Node Address |+
 *   + 1| ------------------][------------------------------------------ |+
 *   + 2| -------------------- 32 byte Public Key ---------------------- |+
 *   + 3| ------------------][- 4 byte seq -][- 4 byte tmp -][- TTL-] FF |+
 *   + 4| .   .   .   .   .   .   .   .   .   .   .   .   .   .   .   .  |+
 *   + 5| .   .   .   .   .   .   .   .   .   .   .   .   .   .   .   .  |+
 *   + 6| .   .   .   .   .   .   .   .   .   .   .   .   .   .   .   .  |+
 *   + 7| .   .   .   .   .   .   .   .   .   .   .   .   .   .   .   .  |+
 *   +--------------------------------------------------------------------+
 *
 *   TOTAL 64 Byte
 */






typedef struct NodeID { uint64_t x[2]; } NodeID;   // 128-bit MAC or UID
typedef struct PubKey { uint8_t x[32]; } PubKey;   // 256-bit Public Key
typedef struct PrivKey { uint8_t x[32]; } PrivKey; // 256-bit Private Key
typedef struct AESKey { uint8_t x[32]; } AESKey;   // 256-bit AES Shared Key



struct HelloPacket {
    NodeID sender_id;
    uint32_t seq_no;
    PubKey pubkey;
    uint32_t timestamp;
};



struct Neighbor {
    NodeID id;
    PubKey pubkey;
    AESKey shared_key;  // Derived via ECDH (or hybrid RSA + random AES)
    uint32_t last_hello_seq;
    uint32_t last_seen;
};





