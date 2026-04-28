#include <stdint.h>
#include "dnsredir.h"
#include <windivert.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <stdio.h>
#include <string.h>

#define TRACK_SIZE 65536

// DNS is redirected to Yandex DNS on port 1253 (non-standard port).
// Türk Telekom blocks port 53 and 5353 to external DNS servers,
// but does NOT block port 1253, which is what GoodbyeDPI Turkey uses.
#define DNS_REDIRECT_IP_V4   "77.88.8.8"           // Yandex DNS IPv4
#define DNS_REDIRECT_IP_V6   "2a02:6b8::feed:0ff"  // Yandex DNS IPv6
#define DNS_REDIRECT_PORT    1253                   // Non-standard port TT doesn't block

typedef struct {
    uint16_t srcPort;
    uint32_t originalDstIp[4];
    BOOL isIpv6;
    BOOL active;
} DnsConn;

static DnsConn g_conns[TRACK_SIZE];
static CRITICAL_SECTION g_connLock;
static HANDLE g_hDivert = INVALID_HANDLE_VALUE;
static HANDLE g_hThread = NULL;
static BOOL g_isRunning = FALSE;

typedef HANDLE (*PWinDivertOpen)(const char *filter, WINDIVERT_LAYER layer, INT16 priority, UINT64 flags);
typedef BOOL (*PWinDivertRecv)(HANDLE handle, VOID *pPacket, UINT packetLen, UINT *pRecvLen, WINDIVERT_ADDRESS *pAddr);
typedef BOOL (*PWinDivertSend)(HANDLE handle, const VOID *pPacket, UINT packetLen, UINT *pSendLen, const WINDIVERT_ADDRESS *pAddr);
typedef BOOL (*PWinDivertClose)(HANDLE handle);
typedef BOOL (*PWinDivertHelperParsePacket)(const VOID *pPacket, UINT packetLen, PWINDIVERT_IPHDR *ppIpHdr, PWINDIVERT_IPV6HDR *ppIpv6Hdr, UINT8 *pProtocol, PWINDIVERT_ICMPHDR *ppIcmpHdr, PWINDIVERT_ICMPV6HDR *ppIcmpv6Hdr, PWINDIVERT_TCPHDR *ppTcpHdr, PWINDIVERT_UDPHDR *ppUdpHdr, PVOID *ppData, UINT *pDataLen, PVOID *ppNext, UINT *pNextLen);
typedef BOOL (*PWinDivertHelperCalcChecksums)(VOID *pPacket, UINT packetLen, WINDIVERT_ADDRESS *pAddr, UINT64 flags);

static PWinDivertOpen pWinDivertOpen = NULL;
static PWinDivertRecv pWinDivertRecv = NULL;
static PWinDivertSend pWinDivertSend = NULL;
static PWinDivertClose pWinDivertClose = NULL;
static PWinDivertHelperParsePacket pWinDivertHelperParsePacket = NULL;
static PWinDivertHelperCalcChecksums pWinDivertHelperCalcChecksums = NULL;
static HMODULE g_hModWinDivert = NULL;

static DWORD WINAPI DnsRedir_Worker(LPVOID lpParam)
{
    char packet[WINDIVERT_MTU_MAX];
    UINT packetLen;
    WINDIVERT_ADDRESS addr;
    uint32_t redir_ipv4;
    uint32_t redir_ipv6[4];

    memset(g_conns, 0, sizeof(g_conns));

    inet_pton(AF_INET,  DNS_REDIRECT_IP_V4, &redir_ipv4);
    inet_pton(AF_INET6, DNS_REDIRECT_IP_V6,  redir_ipv6);

    while (g_isRunning) {
        PWINDIVERT_IPHDR   ip_hdr;
        PWINDIVERT_IPV6HDR ipv6_hdr;
        PWINDIVERT_UDPHDR  udp_hdr;

        if (!pWinDivertRecv(g_hDivert, packet, sizeof(packet), &packetLen, &addr)) {
            continue;
        }

        pWinDivertHelperParsePacket(packet, packetLen,
            &ip_hdr, &ipv6_hdr, NULL, NULL, NULL, NULL,
            &udp_hdr, NULL, NULL, NULL, NULL);

        if (udp_hdr) {
            uint16_t sp = ntohs(udp_hdr->SrcPort);
            uint16_t dp = ntohs(udp_hdr->DstPort);

            if (addr.Outbound && dp == 53) {
                // Outgoing DNS query — rewrite to Yandex DNS on port 1253
                int idx = sp;

                EnterCriticalSection(&g_connLock);
                g_conns[idx].srcPort = udp_hdr->SrcPort;
                g_conns[idx].active  = TRUE;
                g_conns[idx].isIpv6  = (ipv6_hdr != NULL);
                if (ip_hdr) {
                    g_conns[idx].originalDstIp[0] = ip_hdr->DstAddr;
                } else if (ipv6_hdr) {
                    memcpy(g_conns[idx].originalDstIp, ipv6_hdr->DstAddr, 16);
                }
                LeaveCriticalSection(&g_connLock);

                // Rewrite destination port to 1253
                udp_hdr->DstPort = htons(DNS_REDIRECT_PORT);

                if (ip_hdr) {
                    ip_hdr->DstAddr = redir_ipv4;
                } else if (ipv6_hdr) {
                    memcpy(ipv6_hdr->DstAddr, redir_ipv6, 16);
                }

                pWinDivertHelperCalcChecksums(packet, packetLen, &addr, 0);
            }
            else if (!addr.Outbound && sp == DNS_REDIRECT_PORT) {
                // Incoming DNS response from Yandex on port 1253 — restore original source
                uint16_t req_port = ntohs(udp_hdr->DstPort);
                int idx = req_port;
                BOOL shouldProcess = FALSE;

                EnterCriticalSection(&g_connLock);
                if (g_conns[idx].active && g_conns[idx].srcPort == udp_hdr->DstPort) {
                    shouldProcess = TRUE;
                    g_conns[idx].active = FALSE;
                }
                LeaveCriticalSection(&g_connLock);

                if (shouldProcess) {
                    // Rewrite source port back to 53 so Windows stack accepts it
                    udp_hdr->SrcPort = htons(53);

                    EnterCriticalSection(&g_connLock);
                    BOOL     wasIpv6 = g_conns[idx].isIpv6;
                    uint32_t origIp0 = g_conns[idx].originalDstIp[0];
                    uint32_t origIpv6[4];
                    memcpy(origIpv6, g_conns[idx].originalDstIp, 16);
                    LeaveCriticalSection(&g_connLock);

                    if (ip_hdr && !wasIpv6) {
                        ip_hdr->SrcAddr = origIp0;
                    } else if (ipv6_hdr && wasIpv6) {
                        memcpy(ipv6_hdr->SrcAddr, origIpv6, 16);
                    }

                    pWinDivertHelperCalcChecksums(packet, packetLen, &addr, 0);
                }
            }
        }

        pWinDivertSend(g_hDivert, packet, packetLen, NULL, &addr);
    }
    return 0;
}

BOOL DnsRedir_Start(LPCWSTR extractDir)
{
    if (g_isRunning) return TRUE;

    if (!pWinDivertOpen) {
        g_hModWinDivert = LoadLibraryW(L"WinDivert.dll");
        if (!g_hModWinDivert) return FALSE;

        pWinDivertOpen                = (PWinDivertOpen)GetProcAddress(g_hModWinDivert, "WinDivertOpen");
        pWinDivertRecv                = (PWinDivertRecv)GetProcAddress(g_hModWinDivert, "WinDivertRecv");
        pWinDivertSend                = (PWinDivertSend)GetProcAddress(g_hModWinDivert, "WinDivertSend");
        pWinDivertClose               = (PWinDivertClose)GetProcAddress(g_hModWinDivert, "WinDivertClose");
        pWinDivertHelperParsePacket   = (PWinDivertHelperParsePacket)GetProcAddress(g_hModWinDivert, "WinDivertHelperParsePacket");
        pWinDivertHelperCalcChecksums = (PWinDivertHelperCalcChecksums)GetProcAddress(g_hModWinDivert, "WinDivertHelperCalcChecksums");

        if (!pWinDivertOpen || !pWinDivertRecv || !pWinDivertSend || !pWinDivertClose ||
            !pWinDivertHelperParsePacket || !pWinDivertHelperCalcChecksums) {
            FreeLibrary(g_hModWinDivert);
            g_hModWinDivert = NULL;
            return FALSE;
        }
    }

    InitializeCriticalSection(&g_connLock);

    WCHAR oldCwd[MAX_PATH];
    GetCurrentDirectoryW(MAX_PATH, oldCwd);
    SetCurrentDirectoryW(extractDir);

    // Filter: intercept outgoing DNS (port 53) and incoming Yandex responses (port 1253)
    for (int i = 0; i < 10; i++) {
        g_hDivert = pWinDivertOpen(
            "udp.DstPort == 53 or udp.SrcPort == 1253",
            WINDIVERT_LAYER_NETWORK, 10, 0);
        if (g_hDivert != INVALID_HANDLE_VALUE) break;
        Sleep(500);
    }

    SetCurrentDirectoryW(oldCwd);

    if (g_hDivert == INVALID_HANDLE_VALUE) {
        DeleteCriticalSection(&g_connLock);
        return FALSE;
    }

    g_isRunning = TRUE;
    g_hThread = CreateThread(NULL, 0, DnsRedir_Worker, NULL, 0, NULL);
    return TRUE;
}

void DnsRedir_Stop(void)
{
    if (!g_isRunning) return;

    g_isRunning = FALSE;

    if (g_hDivert != INVALID_HANDLE_VALUE && pWinDivertClose) {
        pWinDivertClose(g_hDivert);
        g_hDivert = INVALID_HANDLE_VALUE;
    }

    if (g_hThread) {
        WaitForSingleObject(g_hThread, 1000);
        CloseHandle(g_hThread);
        g_hThread = NULL;
    }

    DeleteCriticalSection(&g_connLock);

    if (g_hModWinDivert) {
        FreeLibrary(g_hModWinDivert);
        g_hModWinDivert = NULL;
        pWinDivertOpen = NULL;
    }
}

BOOL DnsRedir_IsRunning(void)
{
    return g_isRunning;
}
