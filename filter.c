/*++

Copyright (c) Microsoft Corporation

Module Name:

    Filter.c

Abstract:

    Sample NDIS Lightweight filter driver

--*/

#include <ndis.h>
#include <stdlib.h>  // Для rand()

// Типы генерируемых ответов
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

// Очередь и таймер
LIST_ENTRY g_PacketQueue;
KSPIN_LOCK g_QueueLock;
KTIMER g_ReplyTimer;
KDPC g_ReplyDpc;
NDIS_HANDLE g_NdisFilterHandle;

// Прототипы функций
BOOLEAN IsIcmpEchoRequest(PUCHAR PacketData);
BOOLEAN IsTcpSyn(PUCHAR PacketData);
BOOLEAN IsArpRequest(PUCHAR PacketData);
VOID ScheduleFakeReply(PNET_BUFFER_LIST NetBufferList, REPLY_TYPE ReplyType);
VOID TimerDpcRoutine(PKDPC Dpc, PVOID Context, PVOID Arg1, PVOID Arg2);
PNET_BUFFER_LIST GenerateFakeReply(PNET_BUFFER_LIST OriginalPacket, REPLY_TYPE ReplyType);
VOID GenerateStableArpReply(PNET_BUFFER_LIST ArpRequest);


#include "precomp.h"

#define __FILENUMBER    'PNPF'

// This directive puts the DriverEntry function into the INIT segment of the
// driver.  To conserve memory, the code will be discarded when the driver's
// DriverEntry function returns.  You can declare other functions used only
// during initialization here.
#pragma NDIS_INIT_FUNCTION(DriverEntry)

//
// Global variables
//
NDIS_HANDLE         FilterDriverHandle; // NDIS handle for filter driver
NDIS_HANDLE         FilterDriverObject;
NDIS_HANDLE         NdisFilterDeviceHandle = NULL;
PDEVICE_OBJECT      NdisDeviceObject = NULL;

FILTER_LOCK         FilterListLock;
LIST_ENTRY          FilterModuleList;

NDIS_FILTER_PARTIAL_CHARACTERISTICS DefaultChars = {
{ 0, 0, 0},
      0,
      FilterSendNetBufferLists,
      FilterSendNetBufferListsComplete,
      NULL,
      FilterReceiveNetBufferLists,
      FilterReturnNetBufferLists
};

// <<< ДОБАВИТЬ: Прототипы новых функций

// DPC-функция, вызываемая по таймеру
_Use_decl_annotations_
VOID
GenerateResponseTimerDpc(
    PVOID SystemSpecific1,
    PVOID FunctionContext,
    PVOID SystemSpecific2,
    PVOID SystemSpecific3
);

// Функция, которая ставит в очередь задачу на установку таймера
_Use_decl_annotations_
VOID
ScheduleDelayedResponseWorkItem(
    PVOID WorkItemContext
);

// Функции-помощники для создания конкретных пакетов
_IRQL_requires_max_(DISPATCH_LEVEL)
PNET_BUFFER_LIST
CreateIcmpEchoReply(
    _In_ PFILTER_MODULE_CONTEXT FilterModuleContext,
    _In_ PNET_BUFFER_LIST OriginalNbl
);

_IRQL_requires_max_(DISPATCH_LEVEL)
PNET_BUFFER_LIST
CreateTcpRst(
    _In_ PFILTER_MODULE_CONTEXT FilterModuleContext,
    _In_ PNET_BUFFER_LIST OriginalNbl
);

_IRQL_requires_max_(DISPATCH_LEVEL)
PNET_BUFFER_LIST
CreateArpReply(
    _In_ PFILTER_MODULE_CONTEXT FilterModuleContext,
    _In_ PNET_BUFFER_LIST OriginalNbl
);

_Use_decl_annotations_
NTSTATUS
DriverEntry(
    PDRIVER_OBJECT      DriverObject,
    PUNICODE_STRING     RegistryPath
    )
/*++

Routine Description:

    First entry point to be called, when this driver is loaded.
    Register with NDIS as a filter driver and create a device
    for communication with user-mode.

Arguments:

    DriverObject - pointer to the system's driver object structure
                   for this driver

    RegistryPath - system's registry path for this driver

Return Value:

    STATUS_SUCCESS if all initialization is successful, STATUS_XXX
    error code if not.

--*/
{
    NDIS_STATUS Status;
    NDIS_FILTER_DRIVER_CHARACTERISTICS      FChars;
    NDIS_STRING ServiceName  = RTL_CONSTANT_STRING(FILTER_SERVICE_NAME);
    NDIS_STRING UniqueName   = RTL_CONSTANT_STRING(FILTER_UNIQUE_NAME);
    NDIS_STRING FriendlyName = RTL_CONSTANT_STRING(FILTER_FRIENDLY_NAME);
    BOOLEAN bFalse = FALSE;

    UNREFERENCED_PARAMETER(RegistryPath);

    DEBUGP(DL_TRACE, "===>DriverEntry...\n");

    FilterDriverObject = DriverObject;

    do
    {
        NdisZeroMemory(&FChars, sizeof(NDIS_FILTER_DRIVER_CHARACTERISTICS));
        FChars.Header.Type = NDIS_OBJECT_TYPE_FILTER_DRIVER_CHARACTERISTICS;
        FChars.Header.Size = sizeof(NDIS_FILTER_DRIVER_CHARACTERISTICS);
#if NDIS_SUPPORT_NDIS61
        FChars.Header.Revision = NDIS_FILTER_CHARACTERISTICS_REVISION_2;
#else
        FChars.Header.Revision = NDIS_FILTER_CHARACTERISTICS_REVISION_1;
#endif

        FChars.MajorNdisVersion = FILTER_MAJOR_NDIS_VERSION;
        FChars.MinorNdisVersion = FILTER_MINOR_NDIS_VERSION;
        FChars.MajorDriverVersion = 1;
        FChars.MinorDriverVersion = 0;
        FChars.Flags = 0;

        FChars.FriendlyName = FriendlyName;
        FChars.UniqueName = UniqueName;
        FChars.ServiceName = ServiceName;

        //
        // TODO: Most handlers are optional, however, this sample includes them
        // all for illustrative purposes.  If you do not need a particular 
        // handler, set it to NULL and NDIS will more efficiently pass the
        // operation through on your behalf.
        //
        FChars.SetOptionsHandler = FilterRegisterOptions;
        FChars.AttachHandler = FilterAttach;
        FChars.DetachHandler = FilterDetach;
        FChars.RestartHandler = FilterRestart;
        FChars.PauseHandler = FilterPause;
        FChars.SetFilterModuleOptionsHandler = FilterSetModuleOptions;
        FChars.OidRequestHandler = FilterOidRequest;
        FChars.OidRequestCompleteHandler = FilterOidRequestComplete;
        FChars.CancelOidRequestHandler = FilterCancelOidRequest;

        FChars.SendNetBufferListsHandler = FilterSendNetBufferLists;
        FChars.ReturnNetBufferListsHandler = FilterReturnNetBufferLists;
        FChars.SendNetBufferListsCompleteHandler = FilterSendNetBufferListsComplete;
        FChars.ReceiveNetBufferListsHandler = FilterReceiveNetBufferLists;
        FChars.DevicePnPEventNotifyHandler = FilterDevicePnPEventNotify;
        FChars.NetPnPEventHandler = FilterNetPnPEvent;
        FChars.StatusHandler = FilterStatus;
        FChars.CancelSendNetBufferListsHandler = FilterCancelSendNetBufferLists;

        DriverObject->DriverUnload = FilterUnload;

        FilterDriverHandle = NULL;

        //
        // Initialize spin locks
        //
        FILTER_INIT_LOCK(&FilterListLock);

        InitializeListHead(&FilterModuleList);

        Status = NdisFRegisterFilterDriver(DriverObject,
                                           (NDIS_HANDLE)FilterDriverObject,
                                           &FChars,
                                           &FilterDriverHandle);
        if (Status != NDIS_STATUS_SUCCESS)
        {
            DEBUGP(DL_WARN, "Register filter driver failed.\n");
            break;
        }

        Status = FilterRegisterDevice();

        if (Status != NDIS_STATUS_SUCCESS)
        {
            NdisFDeregisterFilterDriver(FilterDriverHandle);
            FILTER_FREE_LOCK(&FilterListLock);
            DEBUGP(DL_WARN, "Register device for the filter driver failed.\n");
            break;
        }


    }
    while(bFalse);


    DEBUGP(DL_TRACE, "<===DriverEntry, Status = %8x\n", Status);
    return Status;

}

_Use_decl_annotations_
NDIS_STATUS
FilterRegisterOptions(
    NDIS_HANDLE  NdisFilterDriverHandle,
    NDIS_HANDLE  FilterDriverContext
    )
/*++

Routine Description:

    Register optional handlers with NDIS.  This sample does not happen to
    have any optional handlers to register, so this routine does nothing
    and could simply have been omitted.  However, for illustrative purposes,
    it is presented here.

Arguments:

    NdisFilterDriverHandle - pointer the driver handle received from
                             NdisFRegisterFilterDriver

    FilterDriverContext    - pointer to our context passed into
                             NdisFRegisterFilterDriver

Return Value:

    NDIS_STATUS_SUCCESS

--*/
{
    DEBUGP(DL_TRACE, "===>FilterRegisterOptions\n");

    ASSERT(NdisFilterDriverHandle == FilterDriverHandle);
    ASSERT(FilterDriverContext == (NDIS_HANDLE)FilterDriverObject);

    if ((NdisFilterDriverHandle != (NDIS_HANDLE)FilterDriverHandle) ||
        (FilterDriverContext != (NDIS_HANDLE)FilterDriverObject))
    {
        return NDIS_STATUS_INVALID_PARAMETER;
    }

    DEBUGP(DL_TRACE, "<===FilterRegisterOptions\n");

    return NDIS_STATUS_SUCCESS;
}


_Use_decl_annotations_
NDIS_STATUS
FilterAttach(
    NDIS_HANDLE                     NdisFilterHandle,
    NDIS_HANDLE                     FilterDriverContext,
    PNDIS_FILTER_ATTACH_PARAMETERS  AttachParameters

    // Инициализация очереди и таймера
    InitializeListHead(&g_PacketQueue);
    KeInitializeSpinLock(&g_QueueLock);
    KeInitializeTimer(&g_ReplyTimer);
    KeInitializeDpc(&g_ReplyDpc, TimerDpcRoutine, NULL);
    g_NdisFilterHandle = NdisFilterHandle;

    InitializeListHead(&FilterModuleContext->ArpCacheListHead);
    NdisAllocateSpinLock(&FilterModuleContext->ArpCacheLock);

    return NDIS_STATUS_SUCCESS;
    )
/*++

Routine Description:

    Filter attach routine.
    Create filter's context, allocate NetBufferLists and NetBuffer pools and any
    other resources, and read configuration if needed.

Arguments:

    NdisFilterHandle - Specify a handle identifying this instance of the filter. FilterAttach
                       should save this handle. It is a required  parameter in subsequent calls
                       to NdisFxxx functions.
    FilterDriverContext - Filter driver context passed to NdisFRegisterFilterDriver.

    AttachParameters - attach parameters

Return Value:

    NDIS_STATUS_SUCCESS: FilterAttach successfully allocated and initialize data structures
                         for this filter instance.
    NDIS_STATUS_RESOURCES: FilterAttach failed due to insufficient resources.
    NDIS_STATUS_FAILURE: FilterAttach could not set up this instance of this filter and it has called
                         NdisWriteErrorLogEntry with parameters specifying the reason for failure.

N.B.:  FILTER can use NdisRegisterDeviceEx to create a device, so the upper 
    layer can send Irps to the filter.

--*/
{
    PMS_FILTER              pFilter = NULL;
    NDIS_STATUS             Status = NDIS_STATUS_SUCCESS;
    NDIS_FILTER_ATTRIBUTES  FilterAttributes;
    ULONG                   Size;
    BOOLEAN               bFalse = FALSE;

    DEBUGP(DL_TRACE, "===>FilterAttach: NdisFilterHandle %p\n", NdisFilterHandle);

    do
    {
        ASSERT(FilterDriverContext == (NDIS_HANDLE)FilterDriverObject);
        if (FilterDriverContext != (NDIS_HANDLE)FilterDriverObject)
        {
            Status = NDIS_STATUS_INVALID_PARAMETER;
            break;
        }

        // Verify the media type is supported.  This is a last resort; the
        // the filter should never have been bound to an unsupported miniport
        // to begin with.  If this driver is marked as a Mandatory filter (which
        // is the default for this sample; see the INF file), failing to attach 
        // here will leave the network adapter in an unusable state.
        //
        // Your setup/install code should not bind the filter to unsupported
        // media types.
        if ((AttachParameters->MiniportMediaType != NdisMedium802_3)
                && (AttachParameters->MiniportMediaType != NdisMediumWan)
                && (AttachParameters->MiniportMediaType != NdisMediumWirelessWan))
        {
           DEBUGP(DL_ERROR, "Unsupported media type.\n");

           Status = NDIS_STATUS_INVALID_PARAMETER;
           break;
        }

        Size = sizeof(MS_FILTER) +
               AttachParameters->FilterModuleGuidName->Length +
               AttachParameters->BaseMiniportInstanceName->Length +
               AttachParameters->BaseMiniportName->Length;

        pFilter = (PMS_FILTER)FILTER_ALLOC_MEM(NdisFilterHandle, Size);
        if (pFilter == NULL)
        {
            DEBUGP(DL_WARN, "Failed to allocate context structure.\n");
            Status = NDIS_STATUS_RESOURCES;
            break;
        }

        NdisZeroMemory(pFilter, sizeof(MS_FILTER));

        pFilter->FilterModuleName.Length = pFilter->FilterModuleName.MaximumLength = AttachParameters->FilterModuleGuidName->Length;
        pFilter->FilterModuleName.Buffer = (PWSTR)((PUCHAR)pFilter + sizeof(MS_FILTER));
        NdisMoveMemory(pFilter->FilterModuleName.Buffer,
                        AttachParameters->FilterModuleGuidName->Buffer,
                        pFilter->FilterModuleName.Length);



        pFilter->MiniportFriendlyName.Length = pFilter->MiniportFriendlyName.MaximumLength = AttachParameters->BaseMiniportInstanceName->Length;
        pFilter->MiniportFriendlyName.Buffer = (PWSTR)((PUCHAR)pFilter->FilterModuleName.Buffer + pFilter->FilterModuleName.Length);
        NdisMoveMemory(pFilter->MiniportFriendlyName.Buffer,
                        AttachParameters->BaseMiniportInstanceName->Buffer,
                        pFilter->MiniportFriendlyName.Length);


        pFilter->MiniportName.Length = pFilter->MiniportName.MaximumLength = AttachParameters->BaseMiniportName->Length;
        pFilter->MiniportName.Buffer = (PWSTR)((PUCHAR)pFilter->MiniportFriendlyName.Buffer +
                                                   pFilter->MiniportFriendlyName.Length);
        NdisMoveMemory(pFilter->MiniportName.Buffer,
                        AttachParameters->BaseMiniportName->Buffer,
                        pFilter->MiniportName.Length);

        pFilter->MiniportIfIndex = AttachParameters->BaseMiniportIfIndex;
        //
        // The filter should initialize TrackReceives and TrackSends properly. For this
        // driver, since its default characteristic has both a send and a receive handler,
        // these fields are initialized to TRUE.
        //
        pFilter->TrackReceives = TRUE;
        pFilter->TrackSends = TRUE;
        pFilter->FilterHandle = NdisFilterHandle;


        NdisZeroMemory(&FilterAttributes, sizeof(NDIS_FILTER_ATTRIBUTES));
        FilterAttributes.Header.Revision = NDIS_FILTER_ATTRIBUTES_REVISION_1;
        FilterAttributes.Header.Size = sizeof(NDIS_FILTER_ATTRIBUTES);
        FilterAttributes.Header.Type = NDIS_OBJECT_TYPE_FILTER_ATTRIBUTES;
        FilterAttributes.Flags = 0;

        NDIS_DECLARE_FILTER_MODULE_CONTEXT(MS_FILTER);
        Status = NdisFSetAttributes(NdisFilterHandle,
                                    pFilter,
                                    &FilterAttributes);
        if (Status != NDIS_STATUS_SUCCESS)
        {
            DEBUGP(DL_WARN, "Failed to set attributes.\n");
            break;
        }


        pFilter->State = FilterPaused;

        FILTER_ACQUIRE_LOCK(&FilterListLock, bFalse);
        InsertHeadList(&FilterModuleList, &pFilter->FilterModuleLink);
        FILTER_RELEASE_LOCK(&FilterListLock, bFalse);

    }
    while (bFalse);

    if (Status != NDIS_STATUS_SUCCESS)
    {
        if (pFilter != NULL)
        {
            FILTER_FREE_MEM(pFilter);
        }
    }

    DEBUGP(DL_TRACE, "<===FilterAttach:    Status %x\n", Status);
    return Status;
}

_Use_decl_annotations_
NDIS_STATUS
FilterPause(
    NDIS_HANDLE                     FilterModuleContext,
    PNDIS_FILTER_PAUSE_PARAMETERS   PauseParameters
    )
/*++

Routine Description:

    Filter pause routine.
    Complete all the outstanding sends and queued sends,
    wait for all the outstanding recvs to be returned
    and return all the queued receives.

Arguments:

    FilterModuleContext - pointer to the filter context stucture
    PauseParameters     - additional information about the pause

Return Value:

    NDIS_STATUS_SUCCESS if filter pauses successfully, NDIS_STATUS_PENDING
    if not.  No other return value is allowed (pause must succeed, eventually).

N.B.: When the filter is in Pausing state, it can still process OID requests, 
    complete sending, and returning packets to NDIS, and also indicate status.
    After this function completes, the filter must not attempt to send or 
    receive packets, but it may still process OID requests and status 
    indications.

--*/
{
    PMS_FILTER          pFilter = (PMS_FILTER)(FilterModuleContext);
    NDIS_STATUS         Status;
    BOOLEAN               bFalse = FALSE;

    UNREFERENCED_PARAMETER(PauseParameters);

    DEBUGP(DL_TRACE, "===>NDISLWF FilterPause: FilterInstance %p\n", FilterModuleContext);

    //
    // Set the flag that the filter is going to pause
    //
    FILTER_ASSERT(pFilter->State == FilterRunning);

    FILTER_ACQUIRE_LOCK(&pFilter->Lock, bFalse);
    pFilter->State = FilterPausing;
    FILTER_RELEASE_LOCK(&pFilter->Lock, bFalse);

    //
    // Do whatever work is required to bring the filter into the Paused state.
    //
    // If you have diverted and queued any send or receive NBLs, return them 
    // now.
    //
    // If you send or receive original NBLs, stop doing that and wait for your
    // NBLs to return to you now.
    //


    Status = NDIS_STATUS_SUCCESS;

    pFilter->State = FilterPaused;

    DEBUGP(DL_TRACE, "<===FilterPause:  Status %x\n", Status);
    return Status;
}

_Use_decl_annotations_
NDIS_STATUS
FilterRestart(
    NDIS_HANDLE                     FilterModuleContext,
    PNDIS_FILTER_RESTART_PARAMETERS RestartParameters
    )
/*++

Routine Description:

    Filter restart routine.
    Start the datapath - begin sending and receiving NBLs.

Arguments:

    FilterModuleContext - pointer to the filter context stucture.
    RestartParameters   - additional information about the restart operation.

Return Value:

    NDIS_STATUS_SUCCESS: if filter restarts successfully
    NDIS_STATUS_XXX: Otherwise.

--*/
{
    NDIS_STATUS     Status;
    PMS_FILTER      pFilter = (PMS_FILTER)FilterModuleContext;
    NDIS_HANDLE     ConfigurationHandle = NULL;


    PNDIS_RESTART_GENERAL_ATTRIBUTES NdisGeneralAttributes;
    PNDIS_RESTART_ATTRIBUTES         NdisRestartAttributes;
    NDIS_CONFIGURATION_OBJECT        ConfigObject;

    DEBUGP(DL_TRACE, "===>FilterRestart:   FilterModuleContext %p\n", FilterModuleContext);

    FILTER_ASSERT(pFilter->State == FilterPaused);

    ConfigObject.Header.Type = NDIS_OBJECT_TYPE_CONFIGURATION_OBJECT;
    ConfigObject.Header.Revision = NDIS_CONFIGURATION_OBJECT_REVISION_1;
    ConfigObject.Header.Size = sizeof(NDIS_CONFIGURATION_OBJECT);
    ConfigObject.NdisHandle = FilterDriverHandle;
    ConfigObject.Flags = 0;

    Status = NdisOpenConfigurationEx(&ConfigObject, &ConfigurationHandle);
    if (Status != NDIS_STATUS_SUCCESS)
    {
        //
        // Filter driver can choose to fail the restart if it cannot open the configuration
        //

#if 0
        //
        // The code is here just to demonstrate how to call NDIS to write an 
        // event to the eventlog.
        //
        PWCHAR              ErrorString = L"Ndislwf";

        DEBUGP(DL_WARN, "FilterRestart: Cannot open configuration.\n");
        NdisWriteEventLogEntry(FilterDriverObject,
                                EVENT_NDIS_DRIVER_FAILURE,
                                0,
                                1,
                                &ErrorString,
                                sizeof(Status),
                                &Status);
#endif

    }

    //
    // This sample doesn't actually do anything with the configuration handle;
    // it is opened here for illustrative purposes.  If you do not need to
    // read configuration, you may omit the code manipulating the 
    // ConfigurationHandle.
    //

    if (Status == NDIS_STATUS_SUCCESS)
    {
        NdisCloseConfiguration(ConfigurationHandle);
    }

    NdisRestartAttributes = RestartParameters->RestartAttributes;

    //
    // If NdisRestartAttributes is not NULL, then the filter can modify generic 
    // attributes and add new media specific info attributes at the end. 
    // Otherwise, if NdisRestartAttributes is NULL, the filter should not try to 
    // modify/add attributes.
    //
    if (NdisRestartAttributes != NULL)
    {
        PNDIS_RESTART_ATTRIBUTES   NextAttributes;

        ASSERT(NdisRestartAttributes->Oid == OID_GEN_MINIPORT_RESTART_ATTRIBUTES);

        NdisGeneralAttributes = (PNDIS_RESTART_GENERAL_ATTRIBUTES)NdisRestartAttributes->Data;

        //
        // Check to see if we need to change any attributes. For example, the
        // driver can change the current MAC address here. Or the driver can add
        // media specific info attributes.
        //
        NdisGeneralAttributes->LookaheadSize = 128;

        //
        // Check each attribute to see whether the filter needs to modify it.
        //
        NextAttributes = NdisRestartAttributes->Next;

        while (NextAttributes != NULL)
        {
            //
            // If somehow the filter needs to change a attributes which requires more space then
            // the current attributes:
            // 1. Remove the attribute from the Attributes list:
            //    TempAttributes = NextAttributes;
            //    NextAttributes = NextAttributes->Next;
            // 2. Free the memory for the current attributes: NdisFreeMemory(TempAttributes, 0 , 0);
            // 3. Dynamically allocate the memory for the new attributes by calling
            //    NdisAllocateMemoryWithTagPriority:
            //    NewAttributes = NdisAllocateMemoryWithTagPriority(Handle, size, Priority);
            // 4. Fill in the new attribute
            // 5. NewAttributes->Next = NextAttributes;
            // 6. NextAttributes = NewAttributes; // Just to make the next statement work.
            //
            NextAttributes = NextAttributes->Next;
        }

        //
        // Add a new attributes at the end
        // 1. Dynamically allocate the memory for the new attributes by calling
        //    NdisAllocateMemoryWithTagPriority.
        // 2. Fill in the new attribute
        // 3. NextAttributes->Next = NewAttributes;
        // 4. NewAttributes->Next = NULL;



    }

    //
    // If everything is OK, set the filter in running state.
    //
    pFilter->State = FilterRunning; // when successful


    Status = NDIS_STATUS_SUCCESS;


    //
    // Ensure the state is Paused if restart failed.
    //

    if (Status != NDIS_STATUS_SUCCESS)
    {
        pFilter->State = FilterPaused;
    }


    DEBUGP(DL_TRACE, "<===FilterRestart:  FilterModuleContext %p, Status %x\n", FilterModuleContext, Status);
    return Status;
}


_Use_decl_annotations_
VOID
FilterDetach(
    NDIS_HANDLE     FilterModuleContext
    )
/*++

Routine Description:

    Filter detach routine.
    This is a required function that will deallocate all the resources allocated during
    FilterAttach. NDIS calls FilterAttach to remove a filter instance from a filter stack.

Arguments:

    FilterModuleContext - pointer to the filter context area.

Return Value:
    None.

NOTE: Called at PASSIVE_LEVEL and the filter is in paused state

--*/
{

    PFILTER_MODULE_CONTEXT filterContext = (PFILTER_MODULE_CONTEXT)FilterModuleContext;
    
    // <<< ДОБАВИТЬ: Очистка ARP-кэша
    ArpCacheCleanup(filterContext);
    NdisFreeSpinLock(&filterContext->ArpCacheLock);


    PMS_FILTER                  pFilter = (PMS_FILTER)FilterModuleContext;
    BOOLEAN                      bFalse = FALSE;


    DEBUGP(DL_TRACE, "===>FilterDetach:    FilterInstance %p\n", FilterModuleContext);


    //
    // Filter must be in paused state
    //
    FILTER_ASSERT(pFilter->State == FilterPaused);


    //
    // Detach must not fail, so do not put any code here that can possibly fail.
    //

    //
    // Free filter instance name if allocated.
    //
    if (pFilter->FilterName.Buffer != NULL)
    {
        FILTER_FREE_MEM(pFilter->FilterName.Buffer);
    }


    FILTER_ACQUIRE_LOCK(&FilterListLock, bFalse);
    RemoveEntryList(&pFilter->FilterModuleLink);
    FILTER_RELEASE_LOCK(&FilterListLock, bFalse);


    //
    // Free the memory allocated
    FILTER_FREE_MEM(pFilter);

    DEBUGP(DL_TRACE, "<===FilterDetach Successfully\n");
    return;
}

_Use_decl_annotations_
BOOLEAN
FilterProcessSendPacket(
    _In_ PFILTER_MODULE_CONTEXT FilterModuleContext,
    _In_ PNET_BUFFER_LIST   NetBufferList
)
{
    BOOLEAN handled = FALSE;
    UCHAR responseType = 0;

    PNET_BUFFER currentNetBuffer = NET_BUFFER_LIST_FIRST_NB(NetBufferList);
    PUCHAR frameBuffer = NdisGetDataBuffer(currentNetBuffer, sizeof(ETHERNET_HEADER), NULL, 1, 0);

    if (frameBuffer == NULL)
    {
        return FALSE; // Не можем получить данные, игнорируем
    }

    ETHERNET_HEADER* ethHeader = (ETHERNET_HEADER*)frameBuffer;
    USHORT etherType = ntohs(ethHeader->Type);

    // Проверяем тип пакета
    if (etherType == ETHERNET_TYPE_ARP)
    {
        ARP_HEADER* arpHeader = (ARP_HEADER*)(frameBuffer + sizeof(ETHERNET_HEADER));
        if (ntohs(arpHeader->Opcode) == ARP_REQUEST)
        {
            responseType = RESPONSE_TYPE_ARP_REPLY;
        }
    }
    else if (etherType == ETHERNET_TYPE_IPV4)
    {
        IPV4_HEADER* ipHeader = (IPV4_HEADER*)(frameBuffer + sizeof(ETHERNET_HEADER));
        ULONG ipHeaderSize = ipHeader->HeaderLength * 4;

        if (ipHeader->Protocol == IPPROTO_ICMP)
        {
            ICMP_HEADER* icmpHeader = (ICMP_HEADER*)((PUCHAR)ipHeader + ipHeaderSize);
            if (icmpHeader->Type == ICMP_ECHO_REQUEST)
            {
                responseType = RESPONSE_TYPE_ICMP_REPLY;
            }
        }
        else if (ipHeader->Protocol == IPPROTO_TCP)
        {
            TCP_HEADER* tcpHeader = (TCP_HEADER*)((PUCHAR)ipHeader + ipHeaderSize);
            if (tcpHeader->Flags & TCP_FLAG_SYN)
            {
                responseType = RESPONSE_TYPE_TCP_RST;
            }
        }
    }

    // Если пакет нужно обработать
    if (responseType != 0)
    {
        PFILTER_REQUEST_CONTEXT context = NdisAllocateMemoryWithTagPriority(
            FilterDriverHandle, 
            sizeof(FILTER_REQUEST_CONTEXT), 
            FILTER_TAG, 
            NormalPoolPriority);

        if (context != NULL)
        {
            RtlZeroMemory(context, sizeof(FILTER_REQUEST_CONTEXT));
            
            context->FilterModuleContext = FilterModuleContext;
            context->OriginalNbl = NetBufferList;
            context->ResponseType = responseType;

            // Инициализируем и ставим в очередь рабочий элемент
            NDIS_HANDLE workItemHandle = NdisAllocateIoWorkItem(FilterDriverHandle);
            if (workItemHandle != NULL)
            {
                context->WorkItem = workItemHandle;
                NdisQueueIoWorkItem(workItemHandle, ScheduleDelayedResponseWorkItem, context);
                handled = TRUE; // Мы обработали этот пакет, не передаем его дальше
            }
            else
            {
                // Не удалось выделить WorkItem, освобождаем контекст
                NdisFreeMemory(context, sizeof(FILTER_REQUEST_CONTEXT), 0);
            }
        }
    }

    // Если handled = TRUE, пакет будет "поглощен"
    // Если handled = FALSE, пакет будет проигнорирован (и отброшен, т.к. мы не вызываем NdisFSendNetBufferLists)
    return handled;
}


_Use_decl_annotations_
VOID
FilterUnload(
    PDRIVER_OBJECT      DriverObject
    )
/*++

Routine Description:

    Filter driver's unload routine.
    Deregister the driver from NDIS.

Arguments:

    DriverObject - pointer to the system's driver object structure
                   for this driver

Return Value:

    NONE

--*/
{
#if DBG
    BOOLEAN               bFalse = FALSE;
#endif

    UNREFERENCED_PARAMETER(DriverObject);

    DEBUGP(DL_TRACE, "===>FilterUnload\n");

    //
    // Should free the filter context list
    //
    FilterDeregisterDevice();
    NdisFDeregisterFilterDriver(FilterDriverHandle);

#if DBG
    FILTER_ACQUIRE_LOCK(&FilterListLock, bFalse);
    ASSERT(IsListEmpty(&FilterModuleList));

    FILTER_RELEASE_LOCK(&FilterListLock, bFalse);

#endif

    FILTER_FREE_LOCK(&FilterListLock);

    DEBUGP(DL_TRACE, "<===FilterUnload\n");

    return;

}

_Use_decl_annotations_
NDIS_STATUS
FilterOidRequest(
    NDIS_HANDLE         FilterModuleContext,
    PNDIS_OID_REQUEST   Request
    )
/*++

Routine Description:

    Request handler
    Handle requests from upper layers

Arguments:

    FilterModuleContext   - our filter
    Request               - the request passed down


Return Value:

     NDIS_STATUS_SUCCESS
     NDIS_STATUS_PENDING
     NDIS_STATUS_XXX

NOTE: Called at <= DISPATCH_LEVEL  (unlike a miniport's MiniportOidRequest)

--*/
{
    PMS_FILTER              pFilter = (PMS_FILTER)FilterModuleContext;
    NDIS_STATUS             Status;
    PNDIS_OID_REQUEST       ClonedRequest=NULL;
    BOOLEAN                 bSubmitted = FALSE;
    PFILTER_REQUEST_CONTEXT Context;
    BOOLEAN                 bFalse = FALSE;


    DEBUGP(DL_TRACE, "===>FilterOidRequest: Request %p.\n", Request);

    //
    // Most of the time, a filter will clone the OID request and pass down
    // the clone.  When the clone completes, the filter completes the original
    // OID request.
    //
    // If your filter needs to modify a specific request, it can modify the
    // request before or after sending down the cloned request.  Or, it can
    // complete the original request on its own without sending down any
    // clone at all.
    //
    // If your filter driver does not need to modify any OID requests, then
    // you may simply omit this routine entirely; NDIS will pass OID requests
    // down on your behalf.  This is more efficient than implementing a 
    // routine that does nothing but clone all requests, as in the sample here.
    //

    do
    {
        Status = NdisAllocateCloneOidRequest(pFilter->FilterHandle,
                                            Request,
                                            FILTER_TAG,
                                            &ClonedRequest);
        if (Status != NDIS_STATUS_SUCCESS)
        {
            DEBUGP(DL_WARN, "FilerOidRequest: Cannot Clone Request\n");
            break;
        }

        Context = (PFILTER_REQUEST_CONTEXT)(&ClonedRequest->SourceReserved[0]);
        *Context = Request;

        bSubmitted = TRUE;

        //
        // Use same request ID
        //
        ClonedRequest->RequestId = Request->RequestId;

        pFilter->PendingOidRequest = ClonedRequest;


        Status = NdisFOidRequest(pFilter->FilterHandle, ClonedRequest);

        if (Status != NDIS_STATUS_PENDING)
        {


            FilterOidRequestComplete(pFilter, ClonedRequest, Status);
            Status = NDIS_STATUS_PENDING;
        }


    }while (bFalse);

    if (bSubmitted == FALSE)
    {
        switch(Request->RequestType)
        {
            case NdisRequestMethod:
                Request->DATA.METHOD_INFORMATION.BytesRead = 0;
                Request->DATA.METHOD_INFORMATION.BytesNeeded = 0;
                Request->DATA.METHOD_INFORMATION.BytesWritten = 0;
                break;

            case NdisRequestSetInformation:
                Request->DATA.SET_INFORMATION.BytesRead = 0;
                Request->DATA.SET_INFORMATION.BytesNeeded = 0;
                break;

            case NdisRequestQueryInformation:
            case NdisRequestQueryStatistics:
            default:
                Request->DATA.QUERY_INFORMATION.BytesWritten = 0;
                Request->DATA.QUERY_INFORMATION.BytesNeeded = 0;
                break;
        }

    }
    DEBUGP(DL_TRACE, "<===FilterOidRequest: Status %8x.\n", Status);

    return Status;

}

_Use_decl_annotations_
VOID
FilterCancelOidRequest(
    NDIS_HANDLE             FilterModuleContext,
    PVOID                   RequestId
    )
/*++

Routine Description:

    Cancels an OID request

    If your filter driver does not intercept and hold onto any OID requests,
    then you do not need to implement this routine.  You may simply omit it.
    Furthermore, if the filter only holds onto OID requests so it can pass
    down a clone (the most common case) the filter does not need to implement 
    this routine; NDIS will then automatically request that the lower-level 
    filter/miniport cancel your cloned OID.

    Most filters do not need to implement this routine.

Arguments:

    FilterModuleContext   - our filter
    RequestId             - identifies the request(s) to cancel

--*/
{
    PMS_FILTER                          pFilter = (PMS_FILTER)FilterModuleContext;
    PNDIS_OID_REQUEST                   Request = NULL;
    PFILTER_REQUEST_CONTEXT             Context;
    PNDIS_OID_REQUEST                   OriginalRequest = NULL;
    BOOLEAN                             bFalse = FALSE;

    FILTER_ACQUIRE_LOCK(&pFilter->Lock, bFalse);

    Request = pFilter->PendingOidRequest;

    if (Request != NULL)
    {
        Context = (PFILTER_REQUEST_CONTEXT)(&Request->SourceReserved[0]);

        OriginalRequest = (*Context);
    }

    if ((OriginalRequest != NULL) && (OriginalRequest->RequestId == RequestId))
    {
        FILTER_RELEASE_LOCK(&pFilter->Lock, bFalse);

        NdisFCancelOidRequest(pFilter->FilterHandle, RequestId);
    }
    else
    {
        FILTER_RELEASE_LOCK(&pFilter->Lock, bFalse);
    }


}

_Use_decl_annotations_
VOID
FilterOidRequestComplete(
    NDIS_HANDLE         FilterModuleContext,
    PNDIS_OID_REQUEST   Request,
    NDIS_STATUS         Status
    )
/*++

Routine Description:

    Notification that an OID request has been completed

    If this filter sends a request down to a lower layer, and the request is
    pended, the FilterOidRequestComplete routine is invoked when the request
    is complete.  Most requests we've sent are simply clones of requests
    received from a higher layer; all we need to do is complete the original
    higher request.

    However, if this filter driver sends original requests down, it must not
    attempt to complete a pending request to the higher layer.

Arguments:

    FilterModuleContext   - our filter context area
    NdisRequest           - the completed request
    Status                - completion status

--*/
{
    PMS_FILTER                          pFilter = (PMS_FILTER)FilterModuleContext;
    PNDIS_OID_REQUEST                   OriginalRequest;
    PFILTER_REQUEST_CONTEXT             Context;
    BOOLEAN                             bFalse = FALSE;

    DEBUGP(DL_TRACE, "===>FilterOidRequestComplete, Request %p.\n", Request);

    Context = (PFILTER_REQUEST_CONTEXT)(&Request->SourceReserved[0]);
    OriginalRequest = (*Context);

    //
    // This is an internal request
    //
    if (OriginalRequest == NULL)
    {
        filterInternalRequestComplete(pFilter, Request, Status);
        return;
    }


    FILTER_ACQUIRE_LOCK(&pFilter->Lock, bFalse);

    ASSERT(pFilter->PendingOidRequest == Request);
    pFilter->PendingOidRequest = NULL;

    FILTER_RELEASE_LOCK(&pFilter->Lock, bFalse);


    //
    // Copy the information from the returned request to the original request
    //
    switch(Request->RequestType)
    {
        case NdisRequestMethod:
            OriginalRequest->DATA.METHOD_INFORMATION.OutputBufferLength =  Request->DATA.METHOD_INFORMATION.OutputBufferLength;
            OriginalRequest->DATA.METHOD_INFORMATION.BytesRead = Request->DATA.METHOD_INFORMATION.BytesRead;
            OriginalRequest->DATA.METHOD_INFORMATION.BytesNeeded = Request->DATA.METHOD_INFORMATION.BytesNeeded;
            OriginalRequest->DATA.METHOD_INFORMATION.BytesWritten = Request->DATA.METHOD_INFORMATION.BytesWritten;
            break;

        case NdisRequestSetInformation:
            OriginalRequest->DATA.SET_INFORMATION.BytesRead = Request->DATA.SET_INFORMATION.BytesRead;
            OriginalRequest->DATA.SET_INFORMATION.BytesNeeded = Request->DATA.SET_INFORMATION.BytesNeeded;
            break;

        case NdisRequestQueryInformation:
        case NdisRequestQueryStatistics:
        default:
            OriginalRequest->DATA.QUERY_INFORMATION.BytesWritten = Request->DATA.QUERY_INFORMATION.BytesWritten;
            OriginalRequest->DATA.QUERY_INFORMATION.BytesNeeded = Request->DATA.QUERY_INFORMATION.BytesNeeded;
            break;
    }


    (*Context) = NULL;

    NdisFreeCloneOidRequest(pFilter->FilterHandle, Request);

    NdisFOidRequestComplete(pFilter->FilterHandle, OriginalRequest, Status);

    DEBUGP(DL_TRACE, "<===FilterOidRequestComplete.\n");
}


_Use_decl_annotations_
VOID
FilterStatus(
    NDIS_HANDLE             FilterModuleContext,
    PNDIS_STATUS_INDICATION StatusIndication
    )
/*++

Routine Description:

    Status indication handler

Arguments:

    FilterModuleContext     - our filter context
    StatusIndication        - the status being indicated

NOTE: called at <= DISPATCH_LEVEL

  FILTER driver may call NdisFIndicateStatus to generate a status indication to 
  all higher layer modules.

--*/
{
    PMS_FILTER              pFilter = (PMS_FILTER)FilterModuleContext;
#if DBG
    BOOLEAN                  bFalse = FALSE;
#endif

    DEBUGP(DL_TRACE, "===>FilterStatus, IndicateStatus = %8x.\n", StatusIndication->StatusCode);


    //
    // The filter may do processing on the status indication here, including
    // intercepting and dropping it entirely.  However, the sample does nothing
    // with status indications except pass them up to the higher layer.  It is 
    // more efficient to omit the FilterStatus handler entirely if it does 
    // nothing, but it is included in this sample for illustrative purposes.
    //

#if DBG
    FILTER_ACQUIRE_LOCK(&pFilter->Lock, bFalse);
    ASSERT(pFilter->bIndicating == FALSE);
    pFilter->bIndicating = TRUE;
    FILTER_RELEASE_LOCK(&pFilter->Lock, bFalse);
#endif // DBG

    NdisFIndicateStatus(pFilter->FilterHandle, StatusIndication);

#if DBG
    FILTER_ACQUIRE_LOCK(&pFilter->Lock, bFalse);
    ASSERT(pFilter->bIndicating == TRUE);
    pFilter->bIndicating = FALSE;
    FILTER_RELEASE_LOCK(&pFilter->Lock, bFalse);
#endif // DBG

    DEBUGP(DL_TRACE, "<===FilterStatus.\n");

}

_Use_decl_annotations_
VOID
FilterDevicePnPEventNotify(
    NDIS_HANDLE             FilterModuleContext,
    PNET_DEVICE_PNP_EVENT   NetDevicePnPEvent
    )
/*++

Routine Description:

    Device PNP event handler

Arguments:

    FilterModuleContext         - our filter context
    NetDevicePnPEvent           - a Device PnP event

NOTE: called at PASSIVE_LEVEL

--*/
{
    PMS_FILTER             pFilter = (PMS_FILTER)FilterModuleContext;
    NDIS_DEVICE_PNP_EVENT  DevicePnPEvent = NetDevicePnPEvent->DevicePnPEvent;
#if DBG
    BOOLEAN                bFalse = FALSE;
#endif

    DEBUGP(DL_TRACE, "===>FilterDevicePnPEventNotify: NetPnPEvent = %p.\n", NetDevicePnPEvent);

    //
    // The filter may do processing on the event here, including intercepting
    // and dropping it entirely.  However, the sample does nothing with Device
    // PNP events, except pass them down to the next lower* layer.  It is more
    // efficient to omit the FilterDevicePnPEventNotify handler entirely if it
    // does nothing, but it is included in this sample for illustrative purposes.
    //
    // * Trivia: Device PNP events percolate DOWN the stack, instead of upwards
    // like status indications and Net PNP events.  So the next layer is the
    // LOWER layer.
    //

    switch (DevicePnPEvent)
    {

        case NdisDevicePnPEventQueryRemoved:
        case NdisDevicePnPEventRemoved:
        case NdisDevicePnPEventSurpriseRemoved:
        case NdisDevicePnPEventQueryStopped:
        case NdisDevicePnPEventStopped:
        case NdisDevicePnPEventPowerProfileChanged:
        case NdisDevicePnPEventFilterListChanged:

            break;

        default:
            DEBUGP(DL_ERROR, "FilterDevicePnPEventNotify: Invalid event.\n");
            FILTER_ASSERT(bFalse);

            break;
    }

    NdisFDevicePnPEventNotify(pFilter->FilterHandle, NetDevicePnPEvent);

    DEBUGP(DL_TRACE, "<===FilterDevicePnPEventNotify\n");

}

_Use_decl_annotations_
NDIS_STATUS
FilterNetPnPEvent(
    NDIS_HANDLE              FilterModuleContext,
    PNET_PNP_EVENT_NOTIFICATION NetPnPEventNotification
    )
/*++

Routine Description:

    Net PNP event handler

Arguments:

    FilterModuleContext         - our filter context
    NetPnPEventNotification     - a Net PnP event

NOTE: called at PASSIVE_LEVEL

--*/
{
    PMS_FILTER                pFilter = (PMS_FILTER)FilterModuleContext;
    NDIS_STATUS               Status = NDIS_STATUS_SUCCESS;

    //
    // The filter may do processing on the event here, including intercepting 
    // and dropping it entirely.  However, the sample does nothing with Net PNP
    // events, except pass them up to the next higher layer.  It is more
    // efficient to omit the FilterNetPnPEvent handler entirely if it does
    // nothing, but it is included in this sample for illustrative purposes.
    //

    Status = NdisFNetPnPEvent(pFilter->FilterHandle, NetPnPEventNotification);

    return Status;
}

_Use_decl_annotations_
VOID
FilterSendNetBufferListsComplete(
    NDIS_HANDLE         FilterModuleContext,
    PNET_BUFFER_LIST    NetBufferLists,
    ULONG               SendCompleteFlags
    )
/*++

Routine Description:

    Send complete handler

    This routine is invoked whenever the lower layer is finished processing 
    sent NET_BUFFER_LISTs.  If the filter does not need to be involved in the
    send path, you should remove this routine and the FilterSendNetBufferLists
    routine.  NDIS will pass along send packets on behalf of your filter more 
    efficiently than the filter can.

Arguments:

    FilterModuleContext     - our filter context
    NetBufferLists          - a chain of NBLs that are being returned to you
    SendCompleteFlags       - flags (see documentation)

Return Value:

     NONE

--*/
{
    PMS_FILTER         pFilter = (PMS_FILTER)FilterModuleContext;
    ULONG              NumOfSendCompletes = 0;
    BOOLEAN            DispatchLevel;
    PNET_BUFFER_LIST   CurrNbl;

    DEBUGP(DL_TRACE, "===>SendNBLComplete, NetBufferList: %p.\n", NetBufferLists);


    //
    // If your filter injected any send packets into the datapath to be sent,
    // you must identify their NBLs here and remove them from the chain.  Do not
    // attempt to send-complete your NBLs up to the higher layer.
    //

    //
    // If your filter has modified any NBLs (or NBs, MDLs, etc) in your
    // FilterSendNetBufferLists handler, you must undo the modifications here.
    // In general, NBLs must be returned in the same condition in which you had
    // you received them.  (Exceptions: the NBLs can be re-ordered on the linked
    // list, and the scratch fields are don't-care).
    //

    if (pFilter->TrackSends)
    {
        CurrNbl = NetBufferLists;
        while (CurrNbl)
        {
            NumOfSendCompletes++;
            CurrNbl = NET_BUFFER_LIST_NEXT_NBL(CurrNbl);

        }
        DispatchLevel = NDIS_TEST_SEND_AT_DISPATCH_LEVEL(SendCompleteFlags);
        FILTER_ACQUIRE_LOCK(&pFilter->Lock, DispatchLevel);
        pFilter->OutstandingSends -= NumOfSendCompletes;
        FILTER_LOG_SEND_REF(2, pFilter, PrevNbl, pFilter->OutstandingSends);
        FILTER_RELEASE_LOCK(&pFilter->Lock, DispatchLevel);
    }

    // Send complete the NBLs.  If you removed any NBLs from the chain, make
    // sure the chain isn't empty (i.e., NetBufferLists!=NULL).

    NdisFSendNetBufferListsComplete(pFilter->FilterHandle, NetBufferLists, SendCompleteFlags);

    DEBUGP(DL_TRACE, "<===SendNBLComplete.\n");
}


_Use_decl_annotations_
// VOID
// FilterSendNetBufferLists(
//     NDIS_HANDLE         FilterModuleContext,
//     PNET_BUFFER_LIST    NetBufferLists,
//     NDIS_PORT_NUMBER    PortNumber,
//     ULONG               SendFlags
//     )
VOID FilterSendNetBufferLists(
    NDIS_HANDLE FilterModuleContext,
    PNET_BUFFER_LIST NetBufferLists,
    NDIS_PORT_NUMBER PortNumber,
    ULONG SendFlags
) {
    PNET_BUFFER netBuffer = NET_BUFFER_LIST_FIRST_NB(NetBufferLists);
    PUCHAR packetData = NdisGetDataBuffer(netBuffer, NET_BUFFER_DATA_LENGTH(netBuffer), NULL, 1, 0);

    if (IsIcmpEchoRequest(packetData)) {
        ScheduleFakeReply(NetBufferLists, ICMP_REPLY);
    } 
    else if (IsTcpSyn(packetData)) {
        ScheduleFakeReply(NetBufferLists, TCP_RST);
    } 
    else if (IsArpRequest(packetData)) {
        ScheduleFakeReply(NetBufferLists, ARP_REPLY);
    } 
    else {
        // Пропускаем другие пакеты
        NdisFSendNetBufferLists(FilterModuleContext, NetBufferLists, PortNumber, SendFlags);
    }
}
/*++

Routine Description:

    Send Net Buffer List handler
    This function is an optional function for filter drivers. If provided, NDIS
    will call this function to transmit a linked list of NetBuffers, described by a
    NetBufferList, over the network. If this handler is NULL, NDIS will skip calling
    this filter when sending a NetBufferList and will call the next lower 
    driver in the stack.  A filter that doesn't provide a FilerSendNetBufferList
    handler can not originate a send on its own.

Arguments:

    FilterModuleContext     - our filter context area
    NetBufferLists          - a List of NetBufferLists to send
    PortNumber              - Port Number to which this send is targeted
    SendFlags               - specifies if the call is at DISPATCH_LEVEL

--*/
{
    PMS_FILTER          pFilter = (PMS_FILTER)FilterModuleContext;
    PNET_BUFFER_LIST    CurrNbl;
    BOOLEAN             DispatchLevel;
    BOOLEAN             bFalse = FALSE;

    DEBUGP(DL_TRACE, "===>SendNetBufferList: NBL = %p.\n", NetBufferLists);

    do
    {

       DispatchLevel = NDIS_TEST_SEND_AT_DISPATCH_LEVEL(SendFlags);
#if DBG
        //
        // we should never get packets to send if we are not in running state
        //

        FILTER_ACQUIRE_LOCK(&pFilter->Lock, DispatchLevel);
        //
        // If the filter is not in running state, fail the send
        //
        if (pFilter->State != FilterRunning)
        {
            FILTER_RELEASE_LOCK(&pFilter->Lock, DispatchLevel);

            CurrNbl = NetBufferLists;
            while (CurrNbl)
            {
                NET_BUFFER_LIST_STATUS(CurrNbl) = NDIS_STATUS_PAUSED;
                CurrNbl = NET_BUFFER_LIST_NEXT_NBL(CurrNbl);
            }
            NdisFSendNetBufferListsComplete(pFilter->FilterHandle,
                        NetBufferLists,
                        DispatchLevel ? NDIS_SEND_COMPLETE_FLAGS_DISPATCH_LEVEL : 0);
            break;

        }
        FILTER_RELEASE_LOCK(&pFilter->Lock, DispatchLevel);
#endif
        if (pFilter->TrackSends)
        {
            FILTER_ACQUIRE_LOCK(&pFilter->Lock, DispatchLevel);
            CurrNbl = NetBufferLists;
            while (CurrNbl)
            {
                pFilter->OutstandingSends++;
                FILTER_LOG_SEND_REF(1, pFilter, CurrNbl, pFilter->OutstandingSends);

                CurrNbl = NET_BUFFER_LIST_NEXT_NBL(CurrNbl);
            }
            FILTER_RELEASE_LOCK(&pFilter->Lock, DispatchLevel);
        }
        
        //
        // If necessary, queue the NetBufferLists in a local structure for later
        // processing.  However, do not queue them for "too long", or else the
        // system's performance may be degraded.  If you need to hold onto an
        // NBL for an unbounded amount of time, then allocate memory, perform a
        // deep copy, and complete the original NBL.
        //
        
        NdisFSendNetBufferLists(pFilter->FilterHandle, NetBufferLists, PortNumber, SendFlags);


    }
    while (bFalse);

    DEBUGP(DL_TRACE, "<===SendNetBufferList. \n");
}

_Use_decl_annotations_
VOID
FilterReturnNetBufferLists(
    NDIS_HANDLE         FilterModuleContext,
    PNET_BUFFER_LIST    NetBufferLists,
    ULONG               ReturnFlags
    )
/*++

Routine Description:

    FilterReturnNetBufferLists handler.
    FilterReturnNetBufferLists is an optional function. If provided, NDIS calls
    FilterReturnNetBufferLists to return the ownership of one or more NetBufferLists
    and their embedded NetBuffers to the filter driver. If this handler is NULL, NDIS
    will skip calling this filter when returning NetBufferLists to the underlying
    miniport and will call the next lower driver in the stack. A filter that doesn't
    provide a FilterReturnNetBufferLists handler cannot originate a receive indication
    on its own.

Arguments:

    FilterInstanceContext       - our filter context area
    NetBufferLists              - a linked list of NetBufferLists that this 
                                  filter driver indicated in a previous call to 
                                  NdisFIndicateReceiveNetBufferLists
    ReturnFlags                 - flags specifying if the caller is at DISPATCH_LEVEL

--*/
{
    PMS_FILTER          pFilter = (PMS_FILTER)FilterModuleContext;
    PNET_BUFFER_LIST    CurrNbl = NetBufferLists;
    UINT                NumOfNetBufferLists = 0;
    BOOLEAN             DispatchLevel;
    ULONG               Ref;

    DEBUGP(DL_TRACE, "===>ReturnNetBufferLists, NetBufferLists is %p.\n", NetBufferLists);


    //
    // If your filter injected any receive packets into the datapath to be
    // received, you must identify their NBLs here and remove them from the 
    // chain.  Do not attempt to receive-return your NBLs down to the lower
    // layer.
    //

    //
    // If your filter has modified any NBLs (or NBs, MDLs, etc) in your
    // FilterReceiveNetBufferLists handler, you must undo the modifications here.
    // In general, NBLs must be returned in the same condition in which you had
    // you received them.  (Exceptions: the NBLs can be re-ordered on the linked
    // list, and the scratch fields are don't-care).
    //

    if (pFilter->TrackReceives)
    {
        while (CurrNbl)
        {
            NumOfNetBufferLists ++;
            CurrNbl = NET_BUFFER_LIST_NEXT_NBL(CurrNbl);
        }
    }

    
    // Return the received NBLs.  If you removed any NBLs from the chain, make
    // sure the chain isn't empty (i.e., NetBufferLists!=NULL).

    NdisFReturnNetBufferLists(pFilter->FilterHandle, NetBufferLists, ReturnFlags);

    if (pFilter->TrackReceives)
    {
        DispatchLevel = NDIS_TEST_RETURN_AT_DISPATCH_LEVEL(ReturnFlags);
        FILTER_ACQUIRE_LOCK(&pFilter->Lock, DispatchLevel);

        pFilter->OutstandingRcvs -= NumOfNetBufferLists;
        Ref = pFilter->OutstandingRcvs;
        FILTER_LOG_RCV_REF(3, pFilter, NetBufferLists, Ref);
        FILTER_RELEASE_LOCK(&pFilter->Lock, DispatchLevel);
    }


    DEBUGP(DL_TRACE, "<===ReturnNetBufferLists.\n");


}


_Use_decl_annotations_
VOID
FilterReceiveNetBufferLists(
    NDIS_HANDLE         FilterModuleContext,
    PNET_BUFFER_LIST    NetBufferLists,
    NDIS_PORT_NUMBER    PortNumber,
    ULONG               NumberOfNetBufferLists,
    ULONG               ReceiveFlags
    )
/*++

Routine Description:

    FilerReceiveNetBufferLists is an optional function for filter drivers.
    If provided, this function processes receive indications made by underlying
    NIC or lower level filter drivers. This function  can also be called as a
    result of loopback. If this handler is NULL, NDIS will skip calling this
    filter when processing a receive indication and will call the next higher
    driver in the stack. A filter that doesn't provide a
    FilterReceiveNetBufferLists handler cannot provide a
    FilterReturnNetBufferLists handler and cannot a initiate an original receive 
    indication on its own.

Arguments:

    FilterModuleContext      - our filter context area.
    NetBufferLists           - a linked list of NetBufferLists
    PortNumber               - Port on which the receive is indicated
    ReceiveFlags             -

N.B.: It is important to check the ReceiveFlags in NDIS_TEST_RECEIVE_CANNOT_PEND.
    This controls whether the receive indication is an synchronous or 
    asynchronous function call.

--*/
{

    PMS_FILTER          pFilter = (PMS_FILTER)FilterModuleContext;
    BOOLEAN             DispatchLevel;
    ULONG               Ref;
    BOOLEAN             bFalse = FALSE;
#if DBG
    ULONG               ReturnFlags;
#endif

    DEBUGP(DL_TRACE, "===>ReceiveNetBufferList: NetBufferLists = %p.\n", NetBufferLists);
    do
    {

        DispatchLevel = NDIS_TEST_RECEIVE_AT_DISPATCH_LEVEL(ReceiveFlags);
#if DBG
        FILTER_ACQUIRE_LOCK(&pFilter->Lock, DispatchLevel);

        if (pFilter->State != FilterRunning)
        {
            FILTER_RELEASE_LOCK(&pFilter->Lock, DispatchLevel);

            if (NDIS_TEST_RECEIVE_CAN_PEND(ReceiveFlags))
            {
                ReturnFlags = 0;
                if (NDIS_TEST_RECEIVE_AT_DISPATCH_LEVEL(ReceiveFlags))
                {
                    NDIS_SET_RETURN_FLAG(ReturnFlags, NDIS_RETURN_FLAGS_DISPATCH_LEVEL);
                }

                NdisFReturnNetBufferLists(pFilter->FilterHandle, NetBufferLists, ReturnFlags);
            }
            break;
        }
        FILTER_RELEASE_LOCK(&pFilter->Lock, DispatchLevel);
#endif

        ASSERT(NumberOfNetBufferLists >= 1);

        //
        // If you would like to drop a received packet, then you must carefully
        // modify the NBL chain as follows:
        //
        //     if NDIS_TEST_RECEIVE_CANNOT_PEND(ReceiveFlags):
        //         For each NBL that is NOT dropped, temporarily unlink it from
        //         the linked list, and indicate it up alone with 
        //         NdisFIndicateReceiveNetBufferLists and the
        //         NDIS_RECEIVE_FLAGS_RESOURCES flag set.  Then immediately
        //         relink the NBL back into the chain.  When all NBLs have been
        //         indicated up, you may return from this function.
        //     otherwise (NDIS_TEST_RECEIVE_CANNOT_PEND is FALSE):
        //         Divide the linked list of NBLs into two chains: one chain
        //         of packets to drop, and everything else in another chain.
        //         Return the first chain with NdisFReturnNetBufferLists, and
        //         indicate up the rest with NdisFIndicateReceiveNetBufferLists.
        //
        // Note: on the receive path for Ethernet packets, one NBL will have 
        // exactly one NB.  So (assuming you are receiving on Ethernet, or are 
        // attached above Native WiFi) you do not need to worry about dropping
        // one NB, but trying to indicate up the remaining NBs on the same NBL.
        // In other words, if the first NB should be dropped, drop the whole NBL.
        //

        //
        // If you would like to modify a packet, and can do so quickly, you may
        // do it here.  However, make sure you save enough information to undo
        // your modification in the FilterReturnNetBufferLists handler.
        //

        //
        // If necessary, queue the NetBufferLists in a local structure for later
        // processing.  However, do not queue them for "too long", or else the
        // system's performance may be degraded.  If you need to hold onto an
        // NBL for an unbounded amount of time, then allocate memory, perform a
        // deep copy, and return the original NBL.
        //

        if (pFilter->TrackReceives)
        {
            FILTER_ACQUIRE_LOCK(&pFilter->Lock, DispatchLevel);
            pFilter->OutstandingRcvs += NumberOfNetBufferLists;
            Ref = pFilter->OutstandingRcvs;

            FILTER_LOG_RCV_REF(1, pFilter, NetBufferLists, Ref);
            FILTER_RELEASE_LOCK(&pFilter->Lock, DispatchLevel);
        }

        NdisFIndicateReceiveNetBufferLists(
                   pFilter->FilterHandle,
                   NetBufferLists,
                   PortNumber,
                   NumberOfNetBufferLists,
                   ReceiveFlags);


        if (NDIS_TEST_RECEIVE_CANNOT_PEND(ReceiveFlags) &&
            pFilter->TrackReceives)
        {
            FILTER_ACQUIRE_LOCK(&pFilter->Lock, DispatchLevel);
            pFilter->OutstandingRcvs -= NumberOfNetBufferLists;
            Ref = pFilter->OutstandingRcvs;
            FILTER_LOG_RCV_REF(2, pFilter, NetBufferLists, Ref);
            FILTER_RELEASE_LOCK(&pFilter->Lock, DispatchLevel);
        }

    } while (bFalse);

    DEBUGP(DL_TRACE, "<===ReceiveNetBufferList: Flags = %8x.\n", ReceiveFlags);

}


_Use_decl_annotations_
VOID
FilterCancelSendNetBufferLists(
    NDIS_HANDLE             FilterModuleContext,
    PVOID                   CancelId
    )
/*++

Routine Description:

    This function cancels any NET_BUFFER_LISTs pended in the filter and then
    calls the NdisFCancelSendNetBufferLists to propagate the cancel operation.

    If your driver does not queue any send NBLs, you may omit this routine.  
    NDIS will propagate the cancelation on your behalf more efficiently.

Arguments:

    FilterModuleContext      - our filter context area.
    CancelId                 - an identifier for all NBLs that should be dequeued

Return Value:

    None

*/
{
    PMS_FILTER  pFilter = (PMS_FILTER)FilterModuleContext;

    NdisFCancelSendNetBufferLists(pFilter->FilterHandle, CancelId);
}


_Use_decl_annotations_
NDIS_STATUS
FilterSetModuleOptions(
    NDIS_HANDLE             FilterModuleContext
    )
/*++

Routine Description:

    This function set the optional handlers for the filter

Arguments:

    FilterModuleContext: The FilterModuleContext given to NdisFSetAttributes

Return Value:

    NDIS_STATUS_SUCCESS
    NDIS_STATUS_RESOURCES
    NDIS_STATUS_FAILURE

--*/
{
   PMS_FILTER                               pFilter = (PMS_FILTER)FilterModuleContext;
   NDIS_FILTER_PARTIAL_CHARACTERISTICS      OptionalHandlers;
   NDIS_STATUS                              Status = NDIS_STATUS_SUCCESS;
   BOOLEAN                                  bFalse = FALSE;

   //
   // Demonstrate how to change send/receive handlers at runtime.
   //
   if (bFalse)
   {
       UINT      i;


       pFilter->CallsRestart++;

       i = pFilter->CallsRestart % 8;

       pFilter->TrackReceives = TRUE;
       pFilter->TrackSends = TRUE;

       NdisMoveMemory(&OptionalHandlers, &DefaultChars, sizeof(OptionalHandlers));
       OptionalHandlers.Header.Type = NDIS_OBJECT_TYPE_FILTER_PARTIAL_CHARACTERISTICS;
       OptionalHandlers.Header.Size = sizeof(OptionalHandlers);
       switch (i)
       {

            case 0:
                OptionalHandlers.ReceiveNetBufferListsHandler = NULL;
                pFilter->TrackReceives = FALSE;
                break;

            case 1:

                OptionalHandlers.ReturnNetBufferListsHandler = NULL;
                pFilter->TrackReceives = FALSE;
                break;

            case 2:
                OptionalHandlers.SendNetBufferListsHandler = NULL;
                pFilter->TrackSends = FALSE;
                break;

            case 3:
                OptionalHandlers.SendNetBufferListsCompleteHandler = NULL;
                pFilter->TrackSends = FALSE;
                break;

            case 4:
                OptionalHandlers.ReceiveNetBufferListsHandler = NULL;
                OptionalHandlers.ReturnNetBufferListsHandler = NULL;
                break;

            case 5:
                OptionalHandlers.SendNetBufferListsHandler = NULL;
                OptionalHandlers.SendNetBufferListsCompleteHandler = NULL;
                break;

            case 6:

                OptionalHandlers.ReceiveNetBufferListsHandler = NULL;
                OptionalHandlers.ReturnNetBufferListsHandler = NULL;
                OptionalHandlers.SendNetBufferListsHandler = NULL;
                OptionalHandlers.SendNetBufferListsCompleteHandler = NULL;
                break;

            case 7:
                break;
       }
       Status = NdisSetOptionalHandlers(pFilter->FilterHandle, (PNDIS_DRIVER_OPTIONAL_HANDLERS)&OptionalHandlers );
   }
   return Status;
}



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
    )
/*++

Routine Description:

    Utility routine that forms and sends an NDIS_OID_REQUEST to the
    miniport, waits for it to complete, and returns status
    to the caller.

    NOTE: this assumes that the calling routine ensures validity
    of the filter handle until this returns.

Arguments:

    FilterModuleContext - pointer to our filter module context
    RequestType - NdisRequest[Set|Query|method]Information
    Oid - the object being set/queried
    InformationBuffer - data for the request
    InformationBufferLength - length of the above
    OutputBufferLength  - valid only for method request
    MethodId - valid only for method request
    pBytesProcessed - place to return bytes read/written

Return Value:

    Status of the set/query request

--*/
{
    FILTER_REQUEST              FilterRequest;
    PNDIS_OID_REQUEST           NdisRequest = &FilterRequest.Request;
    NDIS_STATUS                 Status;
    BOOLEAN                     bFalse;


    bFalse = FALSE;
    *pBytesProcessed = 0;
    NdisZeroMemory(NdisRequest, sizeof(NDIS_OID_REQUEST));

    NdisInitializeEvent(&FilterRequest.ReqEvent);

    NdisRequest->Header.Type = NDIS_OBJECT_TYPE_OID_REQUEST;
    NdisRequest->Header.Revision = NDIS_OID_REQUEST_REVISION_1;
    NdisRequest->Header.Size = sizeof(NDIS_OID_REQUEST);
    NdisRequest->RequestType = RequestType;

    switch (RequestType)
    {
        case NdisRequestQueryInformation:
             NdisRequest->DATA.QUERY_INFORMATION.Oid = Oid;
             NdisRequest->DATA.QUERY_INFORMATION.InformationBuffer =
                                    InformationBuffer;
             NdisRequest->DATA.QUERY_INFORMATION.InformationBufferLength =
                                    InformationBufferLength;
            break;

        case NdisRequestSetInformation:
             NdisRequest->DATA.SET_INFORMATION.Oid = Oid;
             NdisRequest->DATA.SET_INFORMATION.InformationBuffer =
                                    InformationBuffer;
             NdisRequest->DATA.SET_INFORMATION.InformationBufferLength =
                                    InformationBufferLength;
            break;

        case NdisRequestMethod:
             NdisRequest->DATA.METHOD_INFORMATION.Oid = Oid;
             NdisRequest->DATA.METHOD_INFORMATION.MethodId = MethodId;
             NdisRequest->DATA.METHOD_INFORMATION.InformationBuffer =
                                    InformationBuffer;
             NdisRequest->DATA.METHOD_INFORMATION.InputBufferLength =
                                    InformationBufferLength;
             NdisRequest->DATA.METHOD_INFORMATION.OutputBufferLength = OutputBufferLength;
             break;



        default:
            FILTER_ASSERT(bFalse);
            break;
    }

    NdisRequest->RequestId = (PVOID)FILTER_REQUEST_ID;

    Status = NdisFOidRequest(FilterModuleContext->FilterHandle,
                            NdisRequest);


    if (Status == NDIS_STATUS_PENDING)
    {

        NdisWaitEvent(&FilterRequest.ReqEvent, 0);
        Status = FilterRequest.Status;
    }


    if (Status == NDIS_STATUS_SUCCESS)
    {
        if (RequestType == NdisRequestSetInformation)
        {
            *pBytesProcessed = NdisRequest->DATA.SET_INFORMATION.BytesRead;
        }

        if (RequestType == NdisRequestQueryInformation)
        {
            *pBytesProcessed = NdisRequest->DATA.QUERY_INFORMATION.BytesWritten;
        }

        if (RequestType == NdisRequestMethod)
        {
            *pBytesProcessed = NdisRequest->DATA.METHOD_INFORMATION.BytesWritten;
        }

        //
        // The driver below should set the correct value to BytesWritten
        // or BytesRead. But now, we just truncate the value to InformationBufferLength
        //
        if (RequestType == NdisRequestMethod)
        {
            if (*pBytesProcessed > OutputBufferLength)
            {
                *pBytesProcessed = OutputBufferLength;
            }
        }
        else
        {

            if (*pBytesProcessed > InformationBufferLength)
            {
                *pBytesProcessed = InformationBufferLength;
            }
        }
    }


    return Status;
}

VOID
filterInternalRequestComplete(
    _In_ NDIS_HANDLE                  FilterModuleContext,
    _In_ PNDIS_OID_REQUEST            NdisRequest,
    _In_ NDIS_STATUS                  Status
    )
/*++

Routine Description:

    NDIS entry point indicating completion of a pended NDIS_OID_REQUEST.

Arguments:

    FilterModuleContext - pointer to filter module context
    NdisRequest - pointer to NDIS request
    Status - status of request completion

Return Value:

    None

--*/
{
    PFILTER_REQUEST              FilterRequest;


    UNREFERENCED_PARAMETER(FilterModuleContext);

    //
    //  Get at the request context.
    //
    FilterRequest = CONTAINING_RECORD(NdisRequest, FILTER_REQUEST, Request);

    //
    //  Save away the completion status.
    //
    FilterRequest->Status = Status;

    //
    //  Wake up the thread blocked for this request to complete.
    //
    NdisSetEvent(&FilterRequest->ReqEvent);
}

// Функции проверки пакетов
BOOLEAN IsIcmpEchoRequest(PUCHAR PacketData) {
    PIP_HEADER ipHeader = (PIP_HEADER)PacketData;
    if (ipHeader->Protocol == IPPROTO_ICMP) {
        PICMP_HEADER icmpHeader = (PICMP_HEADER)(PacketData + (ipHeader->IHL * 4));
        return (icmpHeader->Type == ICMP_ECHO_REQUEST);
    }
    return FALSE;
}

BOOLEAN IsTcpSyn(PUCHAR PacketData) {
    PIP_HEADER ipHeader = (PIP_HEADER)PacketData;
    if (ipHeader->Protocol == IPPROTO_TCP) {
        PTCP_HEADER tcpHeader = (PTCP_HEADER)(PacketData + (ipHeader->IHL * 4));
        return (tcpHeader->Flags & TCP_FLAG_SYN) && !(tcpHeader->Flags & TCP_FLAG_ACK);
    }
    return FALSE;
}

BOOLEAN IsArpRequest(PUCHAR PacketData) {
    PARP_HEADER arpHeader = (PARP_HEADER)PacketData;
    return (arpHeader->Operation == ARP_REQUEST);
}


// =============================================
// Генерация фиктивных ответов (ICMP, TCP, ARP)
// =============================================

// Структуры для заголовков (добавить в filter.h или в начало filter.c)
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

typedef struct _ARP_HEADER {
    USHORT  HardwareType;
    USHORT  ProtocolType;
    UCHAR   HardwareSize;
    UCHAR   ProtocolSize;
    USHORT  Operation;
    UCHAR   SenderMac[6];
    ULONG   SenderIp;
    UCHAR   TargetMac[6];
    ULONG   TargetIp;
} ARP_HEADER, *PARP_HEADER;
#pragma pack(pop)

// Функция клонирования пакета
PNET_BUFFER_LIST ClonePacket(PNET_BUFFER_LIST Original) {
    PNET_BUFFER_LIST Clone;
    NDIS_STATUS status = NdisAllocateCloneNetBufferList(Original, NULL, NULL, 0, &Clone);
    if (status != NDIS_STATUS_SUCCESS) {
        DbgPrint("Failed to clone packet!\n");
        return NULL;
    }
    return Clone;
}

// Генерация ICMP Echo Reply
VOID ConvertToIcmpReply(PNET_BUFFER_LIST Packet) {
    PNET_BUFFER nb = NET_BUFFER_LIST_FIRST_NB(Packet);
    PUCHAR data = NdisGetDataBuffer(nb, NET_BUFFER_DATA_LENGTH(nb), NULL, 1, 0);
    PIP_HEADER ipHeader = (PIP_HEADER)data;
    PICMP_HEADER icmpHeader = (PICMP_HEADER)(data + (ipHeader->IHL * 4));

    // Меняем запрос на ответ
    icmpHeader->Type = ICMP_ECHO_REPLY;

    // Обновляем контрольную сумму
    icmpHeader->Checksum = 0;
    icmpHeader->Checksum = IPChecksum((USHORT*)icmpHeader, sizeof(ICMP_HEADER));
}

// Генерация TCP RST
VOID ConvertToTcpRst(PNET_BUFFER_LIST Packet) {
    PNET_BUFFER nb = NET_BUFFER_LIST_FIRST_NB(Packet);
    PUCHAR data = NdisGetDataBuffer(nb, NET_BUFFER_DATA_LENGTH(nb), NULL, 1, 0);
    PIP_HEADER ipHeader = (PIP_HEADER)data;
    PTCP_HEADER tcpHeader = (PTCP_HEADER)(data + (ipHeader->IHL * 4));

    // Устанавливаем флаг RST
    tcpHeader->Flags = TCP_FLAG_RST;

    // Обнуляем ACK/SYN (если они были)
    tcpHeader->AckNum = 0;
    tcpHeader->SeqNum = rand();

    // Пересчитываем контрольную сумму (пропущено для краткости)
}

// Генерация стабильного ARP Reply
VOID GenerateStableArpReply(PNET_BUFFER_LIST Packet) {
    PNET_BUFFER nb = NET_BUFFER_LIST_FIRST_NB(Packet);
    PUCHAR data = NdisGetDataBuffer(nb, NET_BUFFER_DATA_LENGTH(nb), NULL, 1, 0);
    PARP_HEADER arpHeader = (PARP_HEADER)data;

    // Генерируем фиксированный MAC на основе IP
    UCHAR fakeMac[6] = { 0x00, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE + (arpHeader->TargetIp & 0xFF) };

    // Меняем запрос на ответ
    arpHeader->Operation = ARP_REPLY; // ARP Reply = 2

    // Подменяем MAC-адреса
    RtlCopyMemory(arpHeader->SenderMacAddress, fakeMac, 6);
    RtlCopyMemory(arpHeader->TargetMacAddress, arpHeader->SenderMacAddress, 6);

    // Меняем IP местами (ARP Reply должен содержать запрошенный IP в SenderIp)
    ULONG tmpIp = arpHeader->SenderIp;
    arpHeader->SenderIp = arpHeader->TargetIp;
    arpHeader->TargetIp = tmpIp;
}

// Основная функция генерации ответа
PNET_BUFFER_LIST GenerateFakeReply(PNET_BUFFER_LIST Original, REPLY_TYPE ReplyType) {
    PNET_BUFFER_LIST reply = ClonePacket(Original);
    if (!reply) return NULL;

    switch (ReplyType) {
        case ICMP_REPLY:
            ConvertToIcmpReply(reply);
            break;
        case TCP_RST:
            ConvertToTcpRst(reply);
            break;
        case ARP_REPLY:
            GenerateStableArpReply(reply);
            break;
    }

    return reply;
}


// =============================================
// Таймер и DPC (для задержки ответов)
// =============================================

// Инициализация таймера (вызывается в FilterAttach)
VOID InitializeTimerAndQueue() {
    KeInitializeSpinLock(&g_QueueLock);
    InitializeListHead(&g_PacketQueue);
    KeInitializeTimer(&g_ReplyTimer);
    KeInitializeDpc(&g_ReplyDpc, TimerDpcRoutine, NULL);
}

// Запланировать ответ с задержкой
VOID ScheduleFakeReply(PNET_BUFFER_LIST Packet, REPLY_TYPE ReplyType) {
    DELAYED_PACKET* delayedPkt = ExAllocatePoolWithTag(NonPagedPool, sizeof(DELAYED_PACKET), 'PktD');
    if (!delayedPkt) {
        DbgPrint("Failed to allocate delayed packet!\n");
        return;
    }

    delayedPkt->NetBufferList = Packet;
    delayedPkt->ReplyType = ReplyType;

    // Добавляем пакет в очередь
    KLOCK_QUEUE_HANDLE lockHandle;
    KeAcquireSpinLock(&g_QueueLock, &lockHandle);
    InsertTailList(&g_PacketQueue, &delayedPkt->ListEntry);
    KeReleaseSpinLock(&lockHandle, lockHandle);

    // Запускаем таймер на случайную задержку (0-100 мс)
    LARGE_INTEGER delay;
    delay.QuadPart = -10000 * (rand() % 101); // 1 мс = 10'000 тиков (100-ns)
    KeSetTimer(&g_ReplyTimer, delay, &g_ReplyDpc);
}

// Обработчик DPC (вызывается по таймеру)
VOID TimerDpcRoutine(PKDPC Dpc, PVOID Context, PVOID Arg1, PVOID Arg2) {
    UNREFERENCED_PARAMETER(Dpc);
    UNREFERENCED_PARAMETER(Context);
    UNREFERENCED_PARAMETER(Arg1);
    UNREFERENCED_PARAMETER(Arg2);

    KLOCK_QUEUE_HANDLE lockHandle;
    KeAcquireSpinLock(&g_QueueLock, &lockHandle);

    // Обрабатываем все пакеты в очереди
    while (!IsListEmpty(&g_PacketQueue)) {
        PLIST_ENTRY entry = RemoveHeadList(&g_PacketQueue);
        DELAYED_PACKET* delayedPkt = CONTAINING_RECORD(entry, DELAYED_PACKET, ListEntry);

        // Генерируем ответ
        PNET_BUFFER_LIST reply = GenerateFakeReply(delayedPkt->NetBufferList, delayedPkt->ReplyType);
        if (reply) {
            // "Внедряем" ответ в сетевой стек
            NdisFIndicateReceiveNetBufferLists(g_NdisFilterHandle, reply, 0, 1);
        }

        // Освобождаем память
        ExFreePoolWithTag(delayedPkt, 'PktD');
    }

    KeReleaseSpinLock(&lockHandle, lockHandle);
}

// 
_Use_decl_annotations_
VOID
ScheduleDelayedResponseWorkItem(
    PVOID WorkItemContext
)
{
    PFILTER_REQUEST_CONTEXT Context = (PFILTER_REQUEST_CONTEXT)WorkItemContext;
    NDIS_TIMER_CHARACTERISTICS TimerChar;
    NTSTATUS Status;

    // Освобождаем WorkItem, он свою задачу выполнил
    NdisFreeIoWorkItem(Context->WorkItem);
    Context->WorkItem = NULL;

    // Настраиваем таймер
    NdisZeroMemory(&TimerChar, sizeof(TimerChar));
    TimerChar.Header.Type = NDIS_OBJECT_TYPE_TIMER_CHARACTERISTICS;
    TimerChar.Header.Revision = NDIS_TIMER_CHARACTERISTICS_REVISION_1;
    TimerChar.Header.Size = sizeof(TimerChar);
    TimerChar.AllocationTag = FILTER_TAG;
    TimerChar.TimerFunction = GenerateResponseTimerDpc; // Наша DPC-функция
    TimerChar.FunctionContext = Context; // Передаем контекст в DPC

    Status = NdisAllocateTimerObject(FilterDriverHandle, &TimerChar, &Context->TimerObject);
    if (Status != NDIS_STATUS_SUCCESS)
    {
        // Ошибка: освобождаем все ресурсы
        NdisFreeNetBufferList(Context->OriginalNbl, 0);
        NdisFreeMemory(Context, 0, 0);
        return;
    }

    // Генерируем случайную задержку [0, 100] мс
    ULONG delayMs = RandomNumber(0, 100);
    LARGE_INTEGER DueTime;
    // Время в 100-наносекундных интервалах. Отрицательное значение - относительное время.
    DueTime.QuadPart = -((LONGLONG)delayMs * 10000); 

    NdisSetTimerObject(Context->TimerObject, DueTime, 0, NULL);
    // Функция завершается, а DPC сработает позже. Никаких блокировок!
}


// Эта функция вызывается по истечении таймера на уровне IRQL = DISPATCH_LEVEL
_Use_decl_annotations_
VOID
GenerateResponseTimerDpc(
    PVOID SystemSpecific1,
    PVOID FunctionContext,
    PVOID SystemSpecific2,
    PVOID SystemSpecific3
)
{
    UNREFERENCED_PARAMETER(SystemSpecific1);
    UNREFERENCED_PARAMETER(SystemSpecific2);
    UNREFERENCED_PARAMETER(SystemSpecific3);

    PFILTER_REQUEST_CONTEXT Context = (PFILTER_REQUEST_CONTEXT)FunctionContext;
    PFILTER_MODULE_CONTEXT FilterModuleContext = (PFILTER_MODULE_CONTEXT)Context->FilterModuleContext;
    PNET_BUFFER_LIST responseNbl = NULL;

    // В зависимости от типа ответа, вызываем нужный генератор пакетов
    switch (Context->ResponseType)
    {
        case RESPONSE_TYPE_ICMP_REPLY:
            responseNbl = CreateIcmpEchoReply(FilterModuleContext, Context->OriginalNbl);
            break;
        case RESPONSE_TYPE_TCP_RST:
            responseNbl = CreateTcpRst(FilterModuleContext, Context->OriginalNbl);
            break;
        case RESPONSE_TYPE_ARP_REPLY:
            responseNbl = CreateArpReply(FilterModuleContext, Context->OriginalNbl);
            break;
    }

    // Если ответный пакет был успешно создан, "индицируем" его получение
    if (responseNbl != NULL)
    {
        NdisFIndicateReceiveNetBufferLists(
            FilterModuleContext->FilterHandle,
            responseNbl,
            NDIS_DEFAULT_PORT_NUMBER,
            1, // Количество NBL
            0  // Флаги
        );
    }

    // --- КРИТИЧЕСКИ ВАЖНАЯ ОЧИСТКА РЕСУРСОВ ---
    NdisFreeTimerObject(Context->TimerObject);
    NdisFreeNetBufferList(Context->OriginalNbl, 0);
    NdisFreeMemory(Context, 0, 0);
}

// Далее идут функции-хелперы, которые содержат вашу логику создания пакетов.
// Я скопировал ее из ваших старых функций и немного адаптировал.

_IRQL_requires_max_(DISPATCH_LEVEL)
PNET_BUFFER_LIST
CreateIcmpEchoReply(
    _In_ PFILTER_MODULE_CONTEXT FilterModuleContext,
    _In_ PNET_BUFFER_LIST OriginalNbl
)
{
    // Ваша логика создания ICMP Echo Reply
    // ... (скопируйте сюда тело вашей старой функции GenerateIcmpResponse,
    // но вместо NdisMSleep и NdisFIndicateReceiveNetBufferLists,
    // функция должна возвращать созданный PNET_BUFFER_LIST)
    // Пример:
    PNET_BUFFER_LIST newNbl = NULL;
    // ... код аллокации и заполнения ...
    // ...
    // В конце:
    // return newNbl;
    // Если ошибка:
    // return NULL;
    
    // Вот примерная реализация на основе вашего кода:
    PNET_BUFFER_LIST newNbl = NULL;
    PNET_BUFFER newNb = NULL;
    PUCHAR newBuffer = NULL;
    ULONG frameLength = 0;

    PNET_BUFFER originalNb = NET_BUFFER_LIST_FIRST_NB(OriginalNbl);
    frameLength = NET_BUFFER_CURRENT_MDL_LENGTH(originalNb);
    PUCHAR originalBuffer = NdisGetDataBuffer(originalNb, frameLength, NULL, 1, 0);
    if (!originalBuffer) return NULL;

    newNbl = NdisAllocateNetBufferList(FilterModuleContext->NblPool, 0, 0);
    if (!newNbl) return NULL;

    newNb = NdisAllocateNetBuffer(FilterModuleContext->NbPool, NULL, 0, 0);
    if (!newNb) {
        NdisFreeNetBufferList(newNbl, 0);
        return NULL;
    }
    NET_BUFFER_LIST_FIRST_NB(newNbl) = newNb;

    newBuffer = NdisGetDataBuffer(newNb, frameLength, NULL, 1, 0);
    if (!newBuffer) {
        NdisFreeNetBufferList(newNbl, 0); // NdisFreeNetBufferList освободит и NB
        return NULL;
    }
    
    RtlCopyMemory(newBuffer, originalBuffer, frameLength);
    NET_BUFFER_DATA_LENGTH(newNb) = frameLength;

    ETHERNET_HEADER* ethHeader = (ETHERNET_HEADER*)newBuffer;
    IPV4_HEADER* ipHeader = (IPV4_HEADER*)(newBuffer + sizeof(ETHERNET_HEADER));
    ICMP_HEADER* icmpHeader = (ICMP_HEADER*)((PUCHAR)ipHeader + ipHeader->HeaderLength * 4);

    // Swap MAC
    SwapMacAddress(ethHeader->Destination, ethHeader->Source);
    // Swap IP
    SwapIpAddress(&ipHeader->SourceAddress, &ipHeader->DestinationAddress);
    // Set ICMP Echo Reply
    icmpHeader->Type = 0; // Echo Reply
    icmpHeader->Code = 0;
    // Recalculate checksums
    icmpHeader->Checksum = 0;
    icmpHeader->Checksum = CalculateChecksum((PUSHORT)icmpHeader, frameLength - sizeof(ETHERNET_HEADER) - (ipHeader->HeaderLength * 4));
    ipHeader->Checksum = 0;
    ipHeader->Checksum = CalculateChecksum((PUSHORT)ipHeader, ipHeader->HeaderLength * 4);

    return newNbl;
}

_IRQL_requires_max_(DISPATCH_LEVEL)
PNET_BUFFER_LIST
CreateTcpRst(
    _In_ PFILTER_MODULE_CONTEXT FilterModuleContext,
    _In_ PNET_BUFFER_LIST OriginalNbl
)
{
    // Ваша логика создания TCP RST
    // Аналогично CreateIcmpEchoReply, скопируйте и адаптируйте
    // тело вашей старой функции GenerateTcpRstResponse.
    // Не забудьте установить флаги RST, ACK.
    PNET_BUFFER_LIST newNbl = NULL;
    PNET_BUFFER newNb = NULL;
    PUCHAR newBuffer = NULL;
    ULONG frameLength = 0;

    PNET_BUFFER originalNb = NET_BUFFER_LIST_FIRST_NB(OriginalNbl);
    frameLength = NET_BUFFER_CURRENT_MDL_LENGTH(originalNb);
    PUCHAR originalBuffer = NdisGetDataBuffer(originalNb, frameLength, NULL, 1, 0);
    if (!originalBuffer) return NULL;

    // Для RST нам не нужен payload, только заголовки
    ULONG headerLength = sizeof(ETHERNET_HEADER) + sizeof(IPV4_HEADER) + sizeof(TCP_HEADER);
    if (frameLength < headerLength) return NULL; // Пакет слишком мал

    newNbl = NdisAllocateNetBufferList(FilterModuleContext->NblPool, 0, 0);
    if (!newNbl) return NULL;

    newNb = NdisAllocateNetBuffer(FilterModuleContext->NbPool, NULL, 0, 0);
    if (!newNb) {
        NdisFreeNetBufferList(newNbl, 0);
        return NULL;
    }
    NET_BUFFER_LIST_FIRST_NB(newNbl) = newNb;

    newBuffer = NdisGetDataBuffer(newNb, headerLength, NULL, 1, 0);
    if (!newBuffer) {
        NdisFreeNetBufferList(newNbl, 0);
        return NULL;
    }
    
    RtlCopyMemory(newBuffer, originalBuffer, headerLength);
    NET_BUFFER_DATA_LENGTH(newNb) = headerLength;

    ETHERNET_HEADER* ethHeader = (ETHERNET_HEADER*)newBuffer;
    IPV4_HEADER* ipHeader = (IPV4_HEADER*)(newBuffer + sizeof(ETHERNET_HEADER));
    TCP_HEADER* tcpHeader = (TCP_HEADER*)((PUCHAR)ipHeader + sizeof(IPV4_HEADER));

    // Swap MAC and IP
    SwapMacAddress(ethHeader->Destination, ethHeader->Source);
    SwapIpAddress(&ipHeader->SourceAddress, &ipHeader->DestinationAddress);
    SwapPorts(&tcpHeader->SourcePort, &tcpHeader->DestinationPort);

    // Prepare RST packet
    ULONG ackNum = ntohl(tcpHeader->SequenceNumber) + 1; // RST/ACK должен подтверждать SYN
    tcpHeader->SequenceNumber = 0; // RST не имеет sequence number
    tcpHeader->AcknowledgementNumber = htonl(ackNum);
    tcpHeader->Flags = TCP_FLAG_RST | TCP_FLAG_ACK;
    tcpHeader->WindowSize = 0;
    tcpHeader->UrgentPointer = 0;
    
    // Recalculate checksums
    ipHeader->TotalLength = htons(sizeof(IPV4_HEADER) + sizeof(TCP_HEADER));
    ipHeader->Checksum = 0;
    ipHeader->Checksum = CalculateChecksum((PUSHORT)ipHeader, sizeof(IPV4_HEADER));
    
    tcpHeader->Checksum = 0;
    tcpHeader->Checksum = CalculateTcpChecksum(ipHeader, tcpHeader);

    return newNbl;
}

_IRQL_requires_max_(DISPATCH_LEVEL)
PNET_BUFFER_LIST
CreateArpReply(
    _In_ PFILTER_MODULE_CONTEXT FilterModuleContext,
    _In_ PNET_BUFFER_LIST OriginalNbl
)
{
    // Ваша логика создания ARP Reply
    // Аналогично, скопируйте и адаптируйте тело вашей старой
    // функции GenerateArpResponse. Используйте ваш ARP-кэш.
    PNET_BUFFER_LIST newNbl = NULL;
    PNET_BUFFER newNb = NULL;
    PUCHAR newBuffer = NULL;
    ULONG frameLength = sizeof(ETHERNET_HEADER) + sizeof(ARP_HEADER);

    PNET_BUFFER originalNb = NET_BUFFER_LIST_FIRST_NB(OriginalNbl);
    PUCHAR originalBuffer = NdisGetDataBuffer(originalNb, frameLength, NULL, 1, 0);
    if (!originalBuffer) return NULL;

    newNbl = NdisAllocateNetBufferList(FilterModuleContext->NblPool, 0, 0);
    if (!newNbl) return NULL;

    newNb = NdisAllocateNetBuffer(FilterModuleContext->NbPool, NULL, 0, 0);
    if (!newNb) {
        NdisFreeNetBufferList(newNbl, 0);
        return NULL;
    }
    NET_BUFFER_LIST_FIRST_NB(newNbl) = newNb;

    newBuffer = NdisGetDataBuffer(newNb, frameLength, NULL, 1, 0);
    if (!newBuffer) {
        NdisFreeNetBufferList(newNbl, 0);
        return NULL;
    }
    
    RtlCopyMemory(newBuffer, originalBuffer, frameLength);
    NET_BUFFER_DATA_LENGTH(newNb) = frameLength;

    ETHERNET_HEADER* ethHeader = (ETHERNET_HEADER*)newBuffer;
    ARP_HEADER* arpHeader = (ARP_HEADER*)(newBuffer + sizeof(ETHERNET_HEADER));

    // Получаем MAC-адрес из кэша или генерируем новый
    UCHAR targetMac[ETH_ALEN];
    ArpCacheGetMac(FilterModuleContext, arpHeader->TargetIP, targetMac);

    // Заполняем ARP Reply
    arpHeader->Opcode = htons(2); // ARP Reply
    RtlCopyMemory(arpHeader->TargetMAC, arpHeader->SenderMAC, ETH_ALEN);
    RtlCopyMemory(arpHeader->TargetIP, arpHeader->SenderIP, 4);
    RtlCopyMemory(arpHeader->SenderMAC, targetMac, ETH_ALEN);
    // SenderIP уже правильный (тот, о котором спрашивали)

    // Заполняем Ethernet заголовок
    RtlCopyMemory(ethHeader->Destination, ethHeader->Source, ETH_ALEN);
    RtlCopyMemory(ethHeader->Source, targetMac, ETH_ALEN);

    return newNbl;
}
