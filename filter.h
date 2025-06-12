/*++

Copyright (c) Microsoft Corporation

Module Name:

    Filter.h

Abstract:

    This module contains all prototypes and macros for filter code.

Notes:

--*/
#ifndef _FILT_H
#define _FILT_H

#pragma warning(disable:28930) // Unused assignment of pointer, by design in samples
#pragma warning(disable:28931) // Unused assignment of variable, by design in samples

// TODO: Customize these to hint at your component for memory leak tracking.
// These should be treated like a pooltag.
#define FILTER_REQUEST_ID          'RTLF'
#define FILTER_ALLOC_TAG           'tliF'
#define FILTER_TAG                 'dnTF'

// TODO: Specify which version of the NDIS contract you will use here.
// In many cases, 6.0 is the best choice.  You only need to select a later
// version if you need a feature that is not available in 6.0.
//
// Legal values include:
//    6.0  Available starting with Windows Vista RTM
//    6.1  Available starting with Windows Vista SP1 / Windows Server 2008
//    6.20 Available starting with Windows 7 / Windows Server 2008 R2
//    6.30 Available starting with Windows 8 / Windows Server "8"
// Or, just use NDIS_FILTER_MAJOR_VERSION / NDIS_FILTER_MINOR_VERSION
// to pick up whatever version is defined by your build system
// (for example, "-DNDIS630").
#define FILTER_MAJOR_NDIS_VERSION   NDIS_FILTER_MAJOR_VERSION
#define FILTER_MINOR_NDIS_VERSION   NDIS_FILTER_MINOR_VERSION

#pragma once

// <<< ДОБАВИТЬ: Директива для правильного выравнивания структур заголовков
#pragma pack(push, 1)

// <<< ДОБАВИТЬ: Определения констант Ethernet
#define ETH_ALEN 6
#define ETHERNET_TYPE_IPV4 0x0800
#define ETHERNET_TYPE_ARP  0x0806


//
// Global variables
//
extern NDIS_HANDLE         FilterDriverHandle; // NDIS handle for filter driver
extern NDIS_HANDLE         FilterDriverObject;
extern NDIS_HANDLE         NdisFilterDeviceHandle;
extern PDEVICE_OBJECT      NdisDeviceObject;

extern FILTER_LOCK         FilterListLock;
extern LIST_ENTRY          FilterModuleList;




#if NDISLWF
#define FILTER_FRIENDLY_NAME        L"NDIS Sample LightWeight Filter"
// TODO: Customize this to match the GUID in the INF
#define FILTER_UNIQUE_NAME          L"{5cbf81bd-5055-47cd-9055-a76b2b4e3697}" //unique name, quid name
// TODO: Customize this to match the service name in the INF
#define FILTER_SERVICE_NAME         L"NDISLWF"
//
// The filter needs to handle IOCTLs
//
#define LINKNAME_STRING             L"\\DosDevices\\NDISLWF"
#define NTDEVICE_STRING             L"\\Device\\NDISLWF"
#endif


#if NDISLWF1
#define FILTER_FRIENDLY_NAME        L"NDIS Sample LightWeight Filter 1"
#define FILTER_UNIQUE_NAME          L"{5cbf81be-5055-47cd-9055-a76b2b4e3697}" //unique name, quid name
#define FILTER_SERVICE_NAME         L"NDISLWF1"
//
// The filter needs to handle IOCTRLs
//
#define LINKNAME_STRING             L"\\DosDevices\\NDISLWF1"
#define NTDEVICE_STRING             L"\\Device\\NDISLWF1"
#endif

#if NDISMON
#define FILTER_FRIENDLY_NAME        L"NDIS Sample Monitor LightWeight Filter"
#define FILTER_UNIQUE_NAME          L"{5cbf81bf-5055-47cd-9055-a76b2b4e3697}" //unique name, quid name
#define FILTER_SERVICE_NAME         L"NDISMON"
//
// The filter needs to handle IOCTRLs
//
#define LINKNAME_STRING             L"\\DosDevices\\NDISMON"
#define NTDEVICE_STRING             L"\\Device\\NDISMON"
#endif

#if NDISMON1
#define FILTER_FRIENDLY_NAME        L"NDIS Sample Monitor 1 LightWeight Filter"
#define FILTER_UNIQUE_NAME          L"{5cbf81c0-5055-47cd-9055-a76b2b4e3697}" //unique name, quid name
#define FILTER_SERVICE_NAME         L"NDISMON1"
//
// The filter needs to handle IOCTRLs
//
#define LINKNAME_STRING             L"\\DosDevices\\NDISMON1"
#define NTDEVICE_STRING             L"\\Device\\NDISMON1"
#endif


//
// Types and macros to manipulate packet queue
//
typedef struct _QUEUE_ENTRY
{
    struct _QUEUE_ENTRY * Next;
}QUEUE_ENTRY, *PQUEUE_ENTRY;

typedef struct _QUEUE_HEADER
{
    PQUEUE_ENTRY     Head;
    PQUEUE_ENTRY     Tail;
} QUEUE_HEADER, *PQUEUE_HEADER;


#if TRACK_RECEIVES
UINT         filterLogReceiveRefIndex = 0;
ULONG_PTR    filterLogReceiveRef[0x10000];
#endif

#if TRACK_SENDS
UINT         filterLogSendRefIndex = 0;
ULONG_PTR    filterLogSendRef[0x10000];
#endif

#if TRACK_RECEIVES
#define   FILTER_LOG_RCV_REF(_O, _Instance, _NetBufferList, _Ref)    \
    {\
        filterLogReceiveRef[filterLogReceiveRefIndex++] = (ULONG_PTR)(_O); \
        filterLogReceiveRef[filterLogReceiveRefIndex++] = (ULONG_PTR)(_Instance); \
        filterLogReceiveRef[filterLogReceiveRefIndex++] = (ULONG_PTR)(_NetBufferList); \
        filterLogReceiveRef[filterLogReceiveRefIndex++] = (ULONG_PTR)(_Ref); \
        if (filterLogReceiveRefIndex >= (0x10000 - 5))                    \
        {                                                              \
            filterLogReceiveRefIndex = 0;                                 \
        }                                                              \
    }
#else
#define   FILTER_LOG_RCV_REF(_O, _Instance, _NetBufferList, _Ref)
#endif

#if TRACK_SENDS
#define   FILTER_LOG_SEND_REF(_O, _Instance, _NetBufferList, _Ref)    \
    {\
        filterLogSendRef[filterLogSendRefIndex++] = (ULONG_PTR)(_O); \
        filterLogSendRef[filterLogSendRefIndex++] = (ULONG_PTR)(_Instance); \
        filterLogSendRef[filterLogSendRefIndex++] = (ULONG_PTR)(_NetBufferList); \
        filterLogSendRef[filterLogSendRefIndex++] = (ULONG_PTR)(_Ref); \
        if (filterLogSendRefIndex >= (0x10000 - 5))                    \
        {                                                              \
            filterLogSendRefIndex = 0;                                 \
        }                                                              \
    }

#else
#define   FILTER_LOG_SEND_REF(_O, _Instance, _NetBufferList, _Ref)
#endif


//
// DEBUG related macros.
//
#if DBG
#define FILTER_ALLOC_MEM(_NdisHandle, _Size)    \
    filterAuditAllocMem(                        \
            _NdisHandle,                        \
           _Size,                               \
           __FILENUMBER,                        \
           __LINE__);

#define FILTER_FREE_MEM(_pMem)                  \
    filterAuditFreeMem(_pMem);

#else
#define FILTER_ALLOC_MEM(_NdisHandle, _Size)     \
    NdisAllocateMemoryWithTagPriority(_NdisHandle, _Size, FILTER_ALLOC_TAG, LowPoolPriority)

#define FILTER_FREE_MEM(_pMem)    NdisFreeMemory(_pMem, 0, 0)

#endif //DBG

#if DBG_SPIN_LOCK
#define FILTER_INIT_LOCK(_pLock)                          \
    filterAllocateSpinLock(_pLock, __FILENUMBER, __LINE__)

#define FILTER_FREE_LOCK(_pLock)       filterFreeSpinLock(_pLock)


#define FILTER_ACQUIRE_LOCK(_pLock, DispatchLevel)  \
    filterAcquireSpinLock(_pLock, __FILENUMBER, __LINE__, DisaptchLevel)

#define FILTER_RELEASE_LOCK(_pLock, DispatchLevel)      \
    filterReleaseSpinLock(_pLock, __FILENUMBER, __LINE__, DispatchLevel)

#else
#define FILTER_INIT_LOCK(_pLock)      NdisAllocateSpinLock(_pLock)

#define FILTER_FREE_LOCK(_pLock)      NdisFreeSpinLock(_pLock)

#define FILTER_ACQUIRE_LOCK(_pLock, DispatchLevel)              \
    {                                                           \
        if (DispatchLevel)                                      \
        {                                                       \
            NdisDprAcquireSpinLock(_pLock);                     \
        }                                                       \
        else                                                    \
        {                                                       \
            NdisAcquireSpinLock(_pLock);                        \
        }                                                       \
    }

#define FILTER_RELEASE_LOCK(_pLock, DispatchLevel)              \
    {                                                           \
        if (DispatchLevel)                                      \
        {                                                       \
            NdisDprReleaseSpinLock(_pLock);                     \
        }                                                       \
        else                                                    \
        {                                                       \
            NdisReleaseSpinLock(_pLock);                        \
        }                                                       \
    }
#endif //DBG_SPIN_LOCK


#define NET_BUFFER_LIST_LINK_TO_ENTRY(_pNBL)    ((PQUEUE_ENTRY)(NET_BUFFER_LIST_NEXT_NBL(_pNBL)))
#define ENTRY_TO_NET_BUFFER_LIST(_pEnt)         (CONTAINING_RECORD((_pEnt), NET_BUFFER_LIST, Next))

#define InitializeQueueHeader(_QueueHeader)             \
{                                                       \
    (_QueueHeader)->Head = (_QueueHeader)->Tail = NULL; \
}

//
// Macros for queue operations
//
#define IsQueueEmpty(_QueueHeader)      ((_QueueHeader)->Head == NULL)

#define RemoveHeadQueue(_QueueHeader)                   \
    (_QueueHeader)->Head;                               \
    {                                                   \
        PQUEUE_ENTRY pNext;                             \
        ASSERT((_QueueHeader)->Head);                   \
        pNext = (_QueueHeader)->Head->Next;             \
        (_QueueHeader)->Head = pNext;                   \
        if (pNext == NULL)                              \
            (_QueueHeader)->Tail = NULL;                \
    }

#define InsertHeadQueue(_QueueHeader, _QueueEntry)                  \
    {                                                               \
        ((PQUEUE_ENTRY)(_QueueEntry))->Next = (_QueueHeader)->Head; \
        (_QueueHeader)->Head = (PQUEUE_ENTRY)(_QueueEntry);         \
        if ((_QueueHeader)->Tail == NULL)                           \
            (_QueueHeader)->Tail = (PQUEUE_ENTRY)(_QueueEntry);     \
    }

#define InsertTailQueue(_QueueHeader, _QueueEntry)                      \
    {                                                                   \
        ((PQUEUE_ENTRY)(_QueueEntry))->Next = NULL;                     \
        if ((_QueueHeader)->Tail)                                       \
            (_QueueHeader)->Tail->Next = (PQUEUE_ENTRY)(_QueueEntry);   \
        else                                                            \
            (_QueueHeader)->Head = (PQUEUE_ENTRY)(_QueueEntry);         \
        (_QueueHeader)->Tail = (PQUEUE_ENTRY)(_QueueEntry);             \
    }


//
// Enum of filter's states
// Filter can only be in one state at one time
//
typedef enum _FILTER_STATE
{
    FilterStateUnspecified,
    FilterInitialized,
    FilterPausing,
    FilterPaused,
    FilterRunning,
    FilterRestarting,
    FilterDetaching
} FILTER_STATE;


typedef struct _FILTER_REQUEST
{
    NDIS_OID_REQUEST       Request;
    NDIS_EVENT             ReqEvent;
    NDIS_STATUS            Status;
} FILTER_REQUEST, *PFILTER_REQUEST;

// МБ удалить

#define RESPONSE_TYPE_ICMP_REPLY 1
#define RESPONSE_TYPE_TCP_RST    2
#define RESPONSE_TYPE_ARP_REPLY  3

// <<< ДОБАВИТЬ: Константы для кодов операций и типов протоколов
#define ICMP_ECHO_REQUEST 8
#define ARP_REQUEST 1

typedef struct _FILTER_REQUEST_CONTEXT
{
    PVOID                   FilterModuleContext;
    PNET_BUFFER_LIST        OriginalNbl;
    NDIS_IO_WORKITEM        WorkItem;
    
    NDIS_HANDLE             TimerObject;
    UCHAR                   ResponseType;

} FILTER_REQUEST_CONTEXT, *PFILTER_REQUEST_CONTEXT;

typedef struct _FILTER_MODULE_CONTEXT
{
    NDIS_HANDLE             FilterHandle;
    NDIS_HANDLE             NblPool;
    NDIS_HANDLE             NbPool;
    // <<< ДОБАВИТЬ ЭТИ ДВА ПОЛЯ
    LIST_ENTRY              ArpCacheListHead;
    NDIS_SPIN_LOCK          ArpCacheLock;

} FILTER_MODULE_CONTEXT, *PFILTER_MODULE_CONTEXT;

//
// Define the filter struct
//
typedef struct _MS_FILTER
{
    LIST_ENTRY                     FilterModuleLink;
    //Reference to this filter
    ULONG                           RefCount;

    NDIS_HANDLE                     FilterHandle;
    NDIS_STRING                     FilterModuleName;
    NDIS_STRING                     MiniportFriendlyName;
    NDIS_STRING                     MiniportName;
    NET_IFINDEX                     MiniportIfIndex;

    NDIS_STATUS                     Status;
    NDIS_EVENT                      Event;
    ULONG                           BackFillSize;
    FILTER_LOCK                     Lock;    // Lock for protection of state and outstanding sends and recvs

    FILTER_STATE                    State;   // Which state the filter is in
    ULONG                           OutstandingSends;
    ULONG                           OutstandingRequest;
    ULONG                           OutstandingRcvs;
    FILTER_LOCK                     SendLock;
    FILTER_LOCK                     RcvLock;
    QUEUE_HEADER                    SendNBLQueue;
    QUEUE_HEADER                    RcvNBLQueue;


    NDIS_STRING                     FilterName;
    ULONG                           CallsRestart;
    BOOLEAN                         TrackReceives;
    BOOLEAN                         TrackSends;
#if DBG
    BOOLEAN                         bIndicating;
#endif

    PNDIS_OID_REQUEST               PendingOidRequest;

}MS_FILTER, * PMS_FILTER;


typedef struct _FILTER_DEVICE_EXTENSION
{
    ULONG            Signature;
    NDIS_HANDLE      Handle;
} FILTER_DEVICE_EXTENSION, *PFILTER_DEVICE_EXTENSION;


#define FILTER_READY_TO_PAUSE(_Filter)      \
    ((_Filter)->State == FilterPausing)

//
// The driver should maintain a list of NDIS filter handles
//
typedef struct _FL_NDIS_FILTER_LIST
{
    LIST_ENTRY              Link;
    NDIS_HANDLE             ContextHandle;
    NDIS_STRING             FilterInstanceName;
} FL_NDIS_FILTER_LIST, *PFL_NDIS_FILTER_LIST;

//
// The context inside a cloned request
//
typedef struct _NDIS_OID_REQUEST *FILTER_REQUEST_CONTEXT,**PFILTER_REQUEST_CONTEXT;


//
// function prototypes
//
DRIVER_INITIALIZE DriverEntry;

FILTER_SET_OPTIONS FilterRegisterOptions;

FILTER_ATTACH FilterAttach;

FILTER_DETACH FilterDetach;

DRIVER_UNLOAD FilterUnload;

FILTER_RESTART FilterRestart;

FILTER_PAUSE FilterPause;

FILTER_OID_REQUEST FilterOidRequest;

FILTER_CANCEL_OID_REQUEST FilterCancelOidRequest;

FILTER_STATUS FilterStatus;

FILTER_DEVICE_PNP_EVENT_NOTIFY FilterDevicePnPEventNotify;

FILTER_NET_PNP_EVENT FilterNetPnPEvent;

FILTER_OID_REQUEST_COMPLETE FilterOidRequestComplete;

FILTER_SEND_NET_BUFFER_LISTS FilterSendNetBufferLists;

FILTER_RETURN_NET_BUFFER_LISTS FilterReturnNetBufferLists;

FILTER_SEND_NET_BUFFER_LISTS_COMPLETE FilterSendNetBufferListsComplete;

FILTER_RECEIVE_NET_BUFFER_LISTS FilterReceiveNetBufferLists;

FILTER_CANCEL_SEND_NET_BUFFER_LISTS FilterCancelSendNetBufferLists;

FILTER_SET_MODULE_OPTIONS FilterSetModuleOptions;


_IRQL_requires_max_(PASSIVE_LEVEL)
NDIS_STATUS
FilterRegisterDevice(
    VOID
    );

_IRQL_requires_max_(PASSIVE_LEVEL)
VOID
FilterDeregisterDevice(
    VOID
    );

DRIVER_DISPATCH FilterDispatch;

DRIVER_DISPATCH FilterDeviceIoControl;

_IRQL_requires_max_(DISPATCH_LEVEL)
PMS_FILTER
filterFindFilterModule(
    _In_reads_bytes_(BufferLength)
         PUCHAR                   Buffer,
    _In_ ULONG                    BufferLength
    );

_IRQL_requires_max_(DISPATCH_LEVEL)
NDIS_STATUS
filterDoInternalRequest(
    _In_ PMS_FILTER                   FilterModuleContext,
    _In_ NDIS_REQUEST_TYPE            RequestType,
    _In_ NDIS_OID                     Oid,
    _Inout_updates_bytes_to_(InformationBufferLength, *pBytesProcessed)
         PVOID                        InformationBuffer,
    _In_ ULONG                        InformationBufferLength,
    _In_opt_ ULONG                    OutputBufferLength,
    _In_ ULONG                        MethodId,
    _Out_ PULONG                      pBytesProcessed
    );

VOID
filterInternalRequestComplete(
    _In_ NDIS_HANDLE                  FilterModuleContext,
    _In_ PNDIS_OID_REQUEST            NdisRequest,
    _In_ NDIS_STATUS                  Status
    );


// Структуры для заголовков пакетов
#pragma pack(push, 1)
typedef struct _IP_HEADER {
    UCHAR   IHL : 4;
    UCHAR   Version : 4;
    UCHAR   Tos;
    USHORT  TotalLength;
    USHORT  Id;
    USHORT  FragOff;
    UCHAR   TTL;
    UCHAR   Protocol;
    USHORT  Checksum;
    ULONG   SrcIp;
    ULONG   DstIp;
} IP_HEADER, *PIP_HEADER;

typedef struct _ICMP_HEADER {
    UCHAR   Type;
    UCHAR   Code;
    USHORT  Checksum;
    USHORT  Id;
    USHORT  Seq;
} ICMP_HEADER, *PICMP_HEADER;

typedef struct _TCP_HEADER {
    USHORT  SrcPort;
    USHORT  DstPort;
    ULONG   SeqNum;
    ULONG   AckNum;
    UCHAR   DataOff : 4;
    UCHAR   Reserved : 4;
    UCHAR   Flags;
    USHORT  Window;
    USHORT  Checksum;
    USHORT  UrgentPtr;
} TCP_HEADER, *PTCP_HEADER;

// Структура заголовка Ethernet
typedef struct _ETHERNET_HEADER {
    UCHAR Destination[ETH_ALEN];
    UCHAR Source[ETH_ALEN];
    USHORT Type;
} ETHERNET_HEADER, *PETHERNET_HEADER;

// typedef struct _ARP_HEADER {
//     USHORT  HardwareType;
//     USHORT  ProtocolType;
//     UCHAR   HardwareSize;
//     UCHAR   ProtocolSize;
//     USHORT  Operation;
//     UCHAR   SenderMac[6];
//     ULONG   SenderIp;
//     UCHAR   TargetMac[6];
//     ULONG   TargetIp;
// } ARP_HEADER, *PARP_HEADER;

typedef struct _ARP_HEADER {
    USHORT HardwareType;
    USHORT ProtocolType;
    UCHAR HardwareAddressLength;
    UCHAR ProtocolAddressLength;
    USHORT Opcode;
    UCHAR SenderMAC[ETH_ALEN];
    UCHAR SenderIP[4];
    UCHAR TargetMAC[ETH_ALEN];
    UCHAR TargetIP[4];
} ARP_HEADER, *PARP_HEADER;

// <<< ДОБАВИТЬ: Определения констант IP
#define IPPROTO_ICMP 1
#define IPPROTO_TCP  6

// <<< ДОБАВИТЬ: Структура заголовка IPv4
typedef struct _IPV4_HEADER {
    UCHAR HeaderLength : 4;
    UCHAR Version : 4;
    UCHAR TypeOfService;
    USHORT TotalLength;
    USHORT Identification;
    USHORT FlagsAndFragmentOffset;
    UCHAR TimeToLive;
    UCHAR Protocol;
    USHORT Checksum;
    ULONG SourceAddress;
    ULONG DestinationAddress;
} IPV4_HEADER, *PIPV4_HEADER;
#pragma pack(pop)

// Типы ответов
typedef enum {
    ICMP_REPLY,
    TCP_RST,
    ARP_REPLY
} REPLY_TYPE;

// Структура для отложенных пакетов
typedef struct _DELAYED_PACKET {
    LIST_ENTRY ListEntry;
    PNET_BUFFER_LIST NetBufferList;
    REPLY_TYPE ReplyType;
} DELAYED_PACKET;

// Глобальные переменные
extern LIST_ENTRY g_PacketQueue;
extern KSPIN_LOCK g_QueueLock;
extern KTIMER g_ReplyTimer;
extern KDPC g_ReplyDpc;
extern NDIS_HANDLE g_NdisFilterHandle;

// Прототипы функций
BOOLEAN IsIcmpEchoRequest(PUCHAR PacketData);
BOOLEAN IsTcpSyn(PUCHAR PacketData);
BOOLEAN IsArpRequest(PUCHAR PacketData);
VOID ScheduleFakeReply(PNET_BUFFER_LIST NetBufferList, REPLY_TYPE ReplyType);
VOID TimerDpcRoutine(PKDPC Dpc, PVOID Context, PVOID Arg1, PVOID Arg2);
PNET_BUFFER_LIST GenerateFakeReply(PNET_BUFFER_LIST OriginalPacket, REPLY_TYPE ReplyType);
VOID GenerateStableArpReply(PNET_BUFFER_LIST ArpRequest);
VOID InitializeTimerAndQueue(VOID);

#endif  //_FILT_H
