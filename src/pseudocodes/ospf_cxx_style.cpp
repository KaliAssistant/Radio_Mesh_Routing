/*
 * Author: KaliAssistant
 * Github: https://github.com/KaliAssistant
 * Licence: GNU/GPLv3.0
 *
 */


#include <iostream>
#include <stdio.h>


const uint8_t TYPE_L2LAYER_MAGICCODE[2] = {0xC6, 0x5A};       // Header Type Magic Code For DataLink header 0xC65A
const uint8_t TYPE_L3LAYER_MAGICCODE[2] = {0xCC, 0x4A};       // Header Type Magic Code For NetWorking header 0xCC4A
const uint8_t TYPE_HELLOPACKET_MAGICCODE[2] = {0x9A, 0xB8};   // Packet Type Magic Code For HelloPacket 0x9AB8
const uint8_t TYPE_L3PACKET_HEADER_CLEAR[2] = {0xCC, 0xAA};   // L3 Header 0x05-0x06 Packet Type Magic code For Non-Encrypted 0xCCAA
const uint8_t TYPE_L3PACKET_HEADER_CRYPT[2] = {0xBB, 0xDD};   // L3 Header 0x05-0x06 Packet Type Magic code For Encrypted 0xBBDD

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
 *   L3 Header
 *   
 *   +--------------------------- L3 Header ------------------------------+
 *   +    00  01  02  03  04  05  06  07  08  09  0A  0B  0C  0D  0E  0F  +
 *   +--------------------------------------------------------------------+
 *   + 0| .N  .E  .T  CC  4A [-*TYP-][------- 8 byte key hint ------] FF |+
 *   +--------------------------------------------------------------------+
 *   
 *   *TYP: Should be `const uint8_t TYPE_L3PACKET_HEADER_XX[2]`
 *
 *   TOTAL 16 Bytes
 */


/*
 *   L2.5 Packet (L2+L3)
 *   
 *   +-------------------------- L2.5 Packet -----------------------------+
 *   +    00  01  02  03  04  05  06  07  08  09  0A  0B  0C  0D  0E  0F  +
 *   +--------------------------------------------------------------------+
 *   + 0|[------------------------ L2 Header ---------------------------]|+
 *   + 1|[-------------------------L3 Header ---------------------------]|+
 *   + 2|[---------------- L3 Packet Data (Max 208 Bytes) -------------- |+
 *   + ~| ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ |+
 *   + E| --------------------------------------------------------------]|+
 *   + F|[-6 byte L2.5 CheckSum-] FF  x   x   x   x   x   x   x   x   x  |+
 *   +--------------------------------------------------------------------+
 *
 *   MAX 247 Bytes
 */
 

/*
 *   Hello Packet (L3)
 *
 *   +-------------------------- Hello Packet ----------------------------+
 *   +    00  01  02  03  04  05  06  07  08  09  0A  0B  0C  0D  0E  0F  +
 *   +--------------------------------------------------------------------+
 *   + 0| 9A  B8 [--------------------- 16 byte Node Address ----------- |+
 *   + 1| ------][------------------------------------------------------ |+
 *   + 2| 32 byte Public Key ------------------------------------------- |+
 *   + 3| ------][- 4 byte seq -][- 4 byte tmp -][- TTL-][- RandID -] FF |+
 *   +--------------------------------------------------------------------+
 *
 *   TOTAL 64 Bytes
 */

typedef struct NodeID { uint64_t x[2]; } NodeID;    // 128-bit MAC or UID
typedef struct PubKey { uint8_t x[32]; } PubKey;    // 256-bit Public Key
typedef struct PrivKey { uint8_t x[32]; } PrivKey;  // 256-bit Private Key
typedef struct AESKey { uint8_t x[32]; } AESKey;    // 256-bit AES Shared Key
typedef struct ChkSum10 { uint8_t x[10];} ChkSum10; // 10 Bytes CheckSum
typedef struct ChkSum8 { uint8_t x[8];} ChkSum8     // 8 Bytes CheckSum
typedef struct KeyHint8 { uint8_t x[8];} KeyHint8;  // 8 Bytes Key Hint 


struct L2Header {
    /* 16 Bytes */
    const uint8_t header[5] = {
      'D', 'A', 'L',
      TYPE_L2LAYER_MAGICCODE[0],
      TYPE_L2LAYER_MAGICCODE[1]
    };                                                                                    // L2: 0x00-0x04
    ChkSum10 L3ChkSum;                                                                    // L2: 0x05-0x0E
    const uint8_t headerEnd = 0xFF;                                                       // L2: 0x0F
};

struct L3Header {
    /* 16 Bytes */
    const uint8_t header[5] = {
      'N', 'E', 'T',
      TYPE_L3LAYER_MAGICCODE[0],
      TYPE_L3LAYER_MAGICCODE[1]
    };                                                                                    // L3: 0x00-0x04
    uint8_t pktType[2];                                                                   // L3: 0x05-0x06
    KeyHint8 key_hint;                                                                    // L3: 0x07-0x0E
    const uint8_t headEnd = 0xFF;                                                         // L3: 0x0F
};

struct L2D5Packet {
    /* 247 Bytes */
    L2Header l2_header;                                                                   // L2.5: 0x00-0x0F
    L3Header l3_header;                                                                   // L2.5: 0x10-0x1F
    uint8_t pktData[208];                                                                 // L2.5: 0x20-0xEF
    ChkSum8 L2D5ChkSum;                                                                   // L2.5: 0xF0-0xF5
    const uint8_t pktEnd = 0xFF;                                                          // L2.5: 0xF6
};



struct HelloPacket {
    /* 64 Bytes */
    const uint8_t header[2] = {
      TYPE_HELLOPACKET_MAGICCODE[0],
      TYPE_HELLOPACKET_MAGICCODE[1]
    };                                                                                    // L3: 0x00-0x01
    NodeID sender_id;                                                                     // L3: 0x02-0x11
    PubKey pubkey;                                                                        // L3: 0x12-0x31
    uint32_t seq_no;                                                                      // L3: 0x32-0x35
    uint32_t timestamp;                                                                   // L3: 0x36-0x39
    uint8_t ttl_MAX_Nodes;  //  Hops limit, MAX 255 (1 Byte)                              // L3: 0x3A
    uint8_t ttl_CNT_Nodes;  //  Hops count, sender is 0. When CNT=MAX, drop the packet.   // L3: 0x3B
    uint8_t random_id[3];   //  3 byte random UID                                         // L3: 0x3C-0x3E
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




int main() {
  L2Header l2test;
  printf("%x, %x, %x, %x, %x", l2test.header[0], l2test.header[1], l2test.header[2], l2test.header[3], l2test.header[4]);
  return 0;
}
