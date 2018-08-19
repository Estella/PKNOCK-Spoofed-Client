/*******************************************************************************************************/
// Port Knock Client for HMAC SHA256 authenication pknock module apart of xtables-addons/iptables
// Build: gcc -lcrypto knock.c -o knock
// TOKEN = HMAC_SHA256(secret, (hex(srcip)+hex(unixtime/60)))
// Created to allowing pknock to work behind nat firewall and have options for source address.
//
// -Estella Mystagic
/*******************************************************************************************************/
#include <unistd.h>
#include <stdio.h>
#include <sys/socket.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <string.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <time.h>
#include <openssl/hmac.h>
/*******************************************************************************************************/
#define PHI 0x9e3779b9
static uint32_t Q[4096], c = 362436;
/*******************************************************************************************************/
#define PCKT_LEN 93
#define DATA_SIZE 65
/*******************************************************************************************************/
typedef struct PseudoHeader {
  unsigned long int source_ip;
  unsigned long int dest_ip;
  unsigned char reserved;
  unsigned char protocol;
  unsigned short int udp_length;
} PseudoHeader;
/*******************************************************************************************************/
void init_rand(uint32_t x) {
  int i;
  Q[0] = x;
  Q[1] = x + PHI;
  Q[2] = x + PHI + PHI;
  for (i = 3; i < 4096; i++) {
    Q[i] = Q[i - 3] ^ Q[i - 2] ^ PHI ^ i;
  }
}
/*******************************************************************************************************/
uint32_t rand_cmwc(void) {
  uint64_t t, a = 18782LL;
  static uint32_t i = 4095;
  uint32_t x, r = 0xfffffffe;
  i = (i + 1) & 4095;
  t = a * Q[i] + c;
  c = (t >> 32);
  x = t + c;
  if (x < c) {
    x++;
    c++;
  }
  return (Q[i] = r - x);
}
/*******************************************************************************************************/
unsigned short ComputeChecksum(unsigned char *data, int len) {
  long sum = 0;
  unsigned short *t = (unsigned short *)data;
  while(len > 1){
    sum += *t++;
    if (sum & 0x80000000) {
      sum = (sum & 0xFFFF) + (sum >> 16);
    }
    len -= 2;
  }
  if(len) {
    sum += (unsigned short) *((unsigned char *)t);
  }
  while(sum >> 16) {
    sum = (sum & 0xFFFF) + (sum >> 16);
  }
  return ~sum;
}
/*******************************************************************************************************/
struct ip *CreateIPHeader(char *srcip, char *destip) {
  struct ip *ip_header;
  ip_header = (struct ip *)malloc(sizeof(struct ip));
  ip_header->ip_v = 4;
  ip_header->ip_hl = 5;
  ip_header->ip_tos = 0;
  ip_header->ip_len = htons(sizeof(struct ip) + sizeof(struct udphdr) + DATA_SIZE);
  ip_header->ip_id = htonl(rand_cmwc() & 0xFFFFFFFF);
  ip_header->ip_off = 0;
  ip_header->ip_ttl = (64 + (rand_cmwc() % 64));
  ip_header->ip_p = IPPROTO_UDP;
  ip_header->ip_sum = 0;
  inet_pton(AF_INET, srcip, &ip_header->ip_src);
  inet_pton(AF_INET, destip, &ip_header->ip_dst);
  ip_header->ip_sum = ComputeChecksum((unsigned char *)ip_header, ip_header->ip_hl*4);
  return (ip_header);
}
/*******************************************************************************************************/
struct udphdr *CreateUdpHeader(char *destport) {
  struct udphdr *udp_header;
  udp_header = (struct udphdr *)malloc(sizeof(struct udphdr));
  udp_header->source = htons((1024 + (rand_cmwc() % 64510)));
  udp_header->dest = htons(atoi(destport));
  udp_header->len = htons(sizeof(struct udphdr) + DATA_SIZE);
  udp_header->check = htons(0);
  return (udp_header);
}
/*******************************************************************************************************/
void CreateFullHeader(struct udphdr *udp_header, struct ip *ip_header, unsigned char *data) {
  int segment_len = ntohs(ip_header->ip_len) - ip_header->ip_hl*4;
  int header_len = sizeof(PseudoHeader) + segment_len;
  unsigned char *hdr = (unsigned char *)malloc(header_len);
  PseudoHeader *pseudo_header = (PseudoHeader *)hdr;
  pseudo_header->source_ip = ip_header->ip_src.s_addr;
  pseudo_header->dest_ip = ip_header->ip_dst.s_addr;
  pseudo_header->reserved = 0;
  pseudo_header->protocol = ip_header->ip_p;
  pseudo_header->udp_length = htons(segment_len);
  memcpy((hdr + sizeof(PseudoHeader)), (void *)udp_header, 8);
  memcpy((hdr + sizeof(PseudoHeader) + 8), data, DATA_SIZE);
  udp_header->check = ComputeChecksum(hdr, header_len);
  free(hdr);
}
/*******************************************************************************************************/
int main(int argc, char *argv[]) {
  int sd, ix;
  char buffer[PCKT_LEN];
  char data[DATA_SIZE];
  int one = 1;
  srand(time(NULL));
  init_rand(time(NULL));
  struct sockaddr_in to_addr;
  const int *val = &one;
  memset(buffer, 0, PCKT_LEN);
  if(argc != 5) {
    printf("[!] Usage %s <SRC IP> <DST IP/KNOCK SERVER> <KNOCK PORT> <SECRET>\n", argv[0]);
    exit(-1);
  }
  time_t token;
  token = (long)(time(NULL)/60);
  struct in_addr srcip;
  unsigned char d[8];
  if (inet_aton(argv[1], &srcip) == 0) {
    perror("[!] Invalid source address");
    exit(EXIT_FAILURE);
  }
  d[7] = ((token >> 24) & 0xFF);
  d[6] = ((token >> 16) & 0xFF);
  d[5] = ((token >> 8) & 0xFF);
  d[4] = (token & 0xFF);
  d[3] = ((srcip.s_addr >> 24) & 0xFF);
  d[2] = ((srcip.s_addr >> 16) & 0xFF);
  d[1] = ((srcip.s_addr >> 8) & 0xFF);
  d[0] = (srcip.s_addr & 0xFF);
  unsigned char *r;
  int len = 32;
  int i;
  static char h[32];
  r = HMAC(EVP_sha256(), argv[4], strlen((char *)argv[4]), d, 8, NULL, NULL);
    for (i = 0; i < len; i++) {
    sprintf(&(h[i * 2]), "%02x", r[i]);
  }
  sd = socket(PF_INET, SOCK_RAW, IPPROTO_RAW);
  if(sd < 0) {
    perror("[!] socket() error");
    exit(EXIT_FAILURE);
  }
  if(setsockopt(sd, IPPROTO_IP, IP_HDRINCL, val, sizeof(int)) < 0) {
    perror("[!] setsockopt() error");
    close(sd);
    exit(EXIT_FAILURE);
  }
  to_addr.sin_family = AF_INET;
  to_addr.sin_addr.s_addr = inet_addr(argv[2]);
  to_addr.sin_port = htons(atoi(argv[3]));
  struct ip *ip_header = CreateIPHeader(argv[1], argv[2]);
  struct udphdr *udp_header = CreateUdpHeader(argv[3]);
  printf("[*] Spoofing Source IP: %s\n[*] Knock Server IP: %s port: %u\n[*] Knock token: %s\n\n", argv[1], argv[2], atoi(argv[3]), h);
  memset(data, 0x0a, DATA_SIZE);
  memcpy(data, &h, 64);
  CreateFullHeader(udp_header, ip_header, (unsigned char*)data);
  memcpy(buffer, ip_header, sizeof(struct ip));
  memcpy(buffer + sizeof(struct ip), udp_header, 8);
  memcpy(buffer + sizeof(struct ip) + 8, data, DATA_SIZE);
  if (sendto(sd, buffer, sizeof(struct ip) + sizeof(struct udphdr) + DATA_SIZE, 0,  (struct sockaddr *)&to_addr, sizeof(to_addr)) < 0) {
    perror("[!] sendto() error");
  } else {
    printf("[*] Knock sent.\n\n");
  }
  free(ip_header);
  free(udp_header);
  close(sd);
  return 0;
}
/*******************************************************************************************************/
// EOF
