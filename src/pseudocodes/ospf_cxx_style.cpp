/*
 * Author: KaliAssistant
 * Github: https://github.com/KaliAssistant
 * Licence: GNU/GPLv3.0
 *
 */

typedef struct NodeID { uint64_t x[2]; } NodeID;   // 128-bit MAC or UID
typedef struct PubKey { uint8_t x[32]; } PubKey;   // 256-bit Public Key
typedef struct PrivKey { uint8_t x[32]; } PrivKey; // 256-bit Private Key
typedef struct AESKey { uint8_t x[32]; } AESKey;   // 256-bit AES Shared Key

#define TYPE_HELLOPACKET_MAGICCODE 0x9AB8 // Packet Type Magic Code For HelloPacket 0x9AB8

struct HelloPacket {
    NodeID sender_id;
    uint32_t seq_no;
    PubKey pubkey;
    uint32_t timestamp;
};

/*   +------------------------- Hello Packet ---------------------------+
 *   +==================================================================+
 *   +   00  01  02  03  04  05  06  07  08  09  0A  0B  0C  0D  0E  0F +
 *   +==================================================================+
 *   + 0|.H  .E  .L  .L  .O  9A  B8 [--------------------- 16 byte Node|+
 *   + 1| ID ----------------------][----------------------------------|+
 *   + 2|------------------------- 32 byte Public Key -----------------|+
 *   + 3|--------------------------][- 4 byte seq -][- 4byte stmp -] . |+
 *   + 4|.   .   .   .   .   .   .   .   .   .   .   .   .   .   .   . |+
 *   + 5|.   .   .   .   .   .   .   .   .   .   .   .   .   .   .   . |+
 *   + 6|.   .   .   .   .   .   .   .   .   .   .   .   .   .   .   . |+
 *   + 7|.   .   .   .   .   .   .   .   .   .   x   x   x   x   x   x |+
 *   +==================================================================+
 *   +------------------------------------------------------------------+
 */



struct Neighbor {
    NodeID id;
    PubKey pubkey;
    AESKey shared_key;  // Derived via ECDH (or hybrid RSA + random AES)
    uint32_t last_hello_seq;
    uint32_t last_seen;
};





