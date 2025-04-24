/*
 * Author: KaliAssistant
 * Github: https://github.com/KaliAssistant
 * Licence: GNU/GPLv3.0
 *
 */


#define TYPE_L2LAYER_MAGICCODE 0xC6, 0x5A   // Header Type Magic Code For DataLink header 0xC65A
#define TYPE_HELLOPACKET_MAGICCODE  0x9A, 0xB8   // Packet Type Magic Code For HelloPacket 0x9AB8


/*
 *   L2 Header
 *   
 *   +--------------------------- L2 Header ------------------------------+
 *   +    00  01  02  03  04  05  06  07  08  09  0A  0B  0C  0D  0E  0F  +
 *   +--------------------------------------------------------------------+
 *   + 0| .D  .A  .L  C6  5A [--------- 10 Byte L3 CheckSum --------] FF |+
 *   +--------------------------------------------------------------------+
 *   
 *   TOTAL 16 Bytes
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
 *   TOTAL 64 Bytes
 */

typedef struct NodeID { uint64_t x[2]; } NodeID;   // 128-bit MAC or UID
typedef struct PubKey { uint8_t x[32]; } PubKey;   // 256-bit Public Key
typedef struct PrivKey { uint8_t x[32]; } PrivKey; // 256-bit Private Key
typedef struct AESKey { uint8_t x[32]; } AESKey;   // 256-bit AES Shared Key
typedef struct ChkSum10 { uint8_t x[10];} ChkSum10; // 10 Bytes CheckSum 


struct L2Header {
    /* 16 Bytes */
    const header[5] = {0x44, 0x41, 0x4C, TYPE_L2LAYER_MAGICCODE};                         // L2: 0x00-0x04
    ChkSum10 L3ChkSum;                                                                    // L2: 0x05-0x0E
    const uint8_t headEnd = 0xFF;                                                         // L2: 0x0F
};

struct HelloPacket {
    /* 64 Bytes */
    const uint8_t header[5] = {0x4E, 0x45, 0x54, TYPE_HELLOPACKET_MAGICCODE};             // L3: 0x00-0x04
    NodeID sender_id;                                                                     // L3: 0x05-0x14
    PubKey pubkey;                                                                        // L3: 0x15-0x34
    uint32_t seq_no;                                                                      // L3: 0x35-0x38
    uint32_t timestamp;                                                                   // L3: 0x39-0x3C
    uint8_t ttl_MAX_Nodes;  //  Hops limit, MAX 255 (1 Byte)                              // L3: 0x3D
    uint8_t ttl_CNT_Nodes;  //  Hops count, sender is 0. When CNT=MAX, drop the packet.   // L3: 0x3E
    const uint8_t pktEnd = 0xFF;                                                          // L3: 0x3F
};



struct Neighbors {
    NodeID id;
    PubKey pubkey;
    AESKey shared_key;  // Derived via ECDH (or hybrid RSA + random AES)
    uint32_t last_hello_seq;
    uint32_t last_seen;
};


struct RemoteNodes {
    NodeID id;
    NodeID byNeighbor;  // Who Forwarded the Sender's HelloPacket ? -> Neighbors
    PubKey pubkey;
    AESKey shared_key;
    uint8_t hops;
    uint32_t last_seen;
};

