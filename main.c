/*++

Module Name:

    FsFilter.c

Abstract:

    This is the main module of the FsFilter miniFilter driver.

Environment:

    Kernel mode

--*/

#include <fltKernel.h>
#include <dontuse.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
//#include "RBAC_System.h"

#define MAX_FILE_AMOUNT 20
#define MAX_PROCESS_AMOUNT 20
#define MAX_FILE_NAME_LENGTH 2048
#define MAX_PROCESS_NAME_LENGTH 2048

#pragma prefast(disable:__WARNING_ENCODE_MEMBER_FUNCTION_POINTER, "Not valid for kernel mode drivers")


PFLT_FILTER gFilterHandle;
ULONG_PTR OperationStatusCtx = 1;

#define PTDBG_TRACE_ROUTINES            0x00000001
#define PTDBG_TRACE_OPERATION_STATUS    0x00000002

ULONG gTraceFlags = 0;


#define PT_DBG_PRINT( _dbgLevel, _string )          \
    (FlagOn(gTraceFlags,(_dbgLevel)) ?              \
        DbgPrint _string :                          \
        ((int)0))

/*************************************************************************
    Prototypes
*************************************************************************/

EXTERN_C_START

DRIVER_INITIALIZE DriverEntry;
NTSTATUS
DriverEntry(
    _In_ PDRIVER_OBJECT DriverObject,
    _In_ PUNICODE_STRING RegistryPath
);

NTSTATUS
FsFilterInstanceSetup(
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ FLT_INSTANCE_SETUP_FLAGS Flags,
    _In_ DEVICE_TYPE VolumeDeviceType,
    _In_ FLT_FILESYSTEM_TYPE VolumeFilesystemType
);

VOID
FsFilterInstanceTeardownStart(
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ FLT_INSTANCE_TEARDOWN_FLAGS Flags
);

VOID
FsFilterInstanceTeardownComplete(
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ FLT_INSTANCE_TEARDOWN_FLAGS Flags
);

NTSTATUS
FsFilterUnload(
    _In_ FLT_FILTER_UNLOAD_FLAGS Flags
);

NTSTATUS
FsFilterInstanceQueryTeardown(
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ FLT_INSTANCE_QUERY_TEARDOWN_FLAGS Flags
);

FLT_PREOP_CALLBACK_STATUS
FsFilterPreOperation(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID* CompletionContext
);

VOID
FsFilterOperationStatusCallback(
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ PFLT_IO_PARAMETER_BLOCK ParameterSnapshot,
    _In_ NTSTATUS OperationStatus,
    _In_ PVOID RequesterContext
);

FLT_POSTOP_CALLBACK_STATUS
FsFilterPostOperation(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_opt_ PVOID CompletionContext,
    _In_ FLT_POST_OPERATION_FLAGS Flags
);

FLT_PREOP_CALLBACK_STATUS
FsFilterPreOperationNoPostOperation(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID* CompletionContext
);

BOOLEAN
FsFilterDoRequestOperationStatus(
    _In_ PFLT_CALLBACK_DATA Data
);

EXTERN_C_END

//
//  Assign text sections for each routine.
//

#ifdef ALLOC_PRAGMA
#pragma alloc_text(INIT, DriverEntry)
#pragma alloc_text(PAGE, FsFilterUnload)
#pragma alloc_text(PAGE, FsFilterInstanceQueryTeardown)
#pragma alloc_text(PAGE, FsFilterInstanceSetup)
#pragma alloc_text(PAGE, FsFilterInstanceTeardownStart)
#pragma alloc_text(PAGE, FsFilterInstanceTeardownComplete)
#endif

//
//  operation registration
//

CONST FLT_OPERATION_REGISTRATION Callbacks[] = {

    { IRP_MJ_CREATE,
      0,
      FsFilterPreOperation,
      FsFilterPostOperation },

    { IRP_MJ_READ,
      0,
      FsFilterPreOperation,
      FsFilterPostOperation },

    { IRP_MJ_WRITE,
      0,
      FsFilterPreOperation,
      FsFilterPostOperation },
    { IRP_MJ_SET_INFORMATION,
      0,
      FsFilterPreOperation,
      FsFilterPostOperation },
      { IRP_MJ_OPERATION_END }
};

//
//  This defines what we want to filter with FltMgr
//

CONST FLT_REGISTRATION FilterRegistration = {

    sizeof(FLT_REGISTRATION),         //  Size
    FLT_REGISTRATION_VERSION,           //  Version
    0,                                  //  Flags

    NULL,                               //  Context
    Callbacks,                          //  Operation callbacks

    FsFilterUnload,                           //  MiniFilterUnload

    FsFilterInstanceSetup,                    //  InstanceSetup
    // FsFilterInstanceQueryTeardown,            //  InstanceQueryTeardown
    //FsFilterInstanceTeardownStart,            //  InstanceTeardownStart
    //FsFilterInstanceTeardownComplete,         //  InstanceTeardownComplete

    NULL,                               //  GenerateFileName
    NULL,                               //  GenerateDestinationFileName
    NULL                                //  NormalizeNameComponent

};



NTSTATUS
FsFilterInstanceSetup(
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ FLT_INSTANCE_SETUP_FLAGS Flags,
    _In_ DEVICE_TYPE VolumeDeviceType,
    _In_ FLT_FILESYSTEM_TYPE VolumeFilesystemType
)
/*++

Routine Description:

    This routine is called whenever a new instance is created on a volume. This
    gives us a chance to decide if we need to attach to this volume or not.

    If this routine is not defined in the registration structure, automatic
    instances are always created.

Arguments:

    FltObjects - Pointer to the FLT_RELATED_OBJECTS data structure containing
        opaque handles to this filter, instance and its associated volume.

    Flags - Flags describing the reason for this attach request.

Return Value:

    STATUS_SUCCESS - attach
    STATUS_FLT_DO_NOT_ATTACH - do not attach

--*/
{
    UNREFERENCED_PARAMETER(FltObjects);
    UNREFERENCED_PARAMETER(Flags);
    UNREFERENCED_PARAMETER(VolumeDeviceType);
    UNREFERENCED_PARAMETER(VolumeFilesystemType);

    PAGED_CODE();

    PT_DBG_PRINT(PTDBG_TRACE_ROUTINES,
        ("FsFilter!FsFilterInstanceSetup: Entered\n"));

    return STATUS_SUCCESS;
}


NTSTATUS
FsFilterInstanceQueryTeardown(
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ FLT_INSTANCE_QUERY_TEARDOWN_FLAGS Flags
)
/*++

Routine Description:

    This is called when an instance is being manually deleted by a
    call to FltDetachVolume or FilterDetach thereby giving us a
    chance to fail that detach request.

    If this routine is not defined in the registration structure, explicit
    detach requests via FltDetachVolume or FilterDetach will always be
    failed.

Arguments:

    FltObjects - Pointer to the FLT_RELATED_OBJECTS data structure containing
        opaque handles to this filter, instance and its associated volume.

    Flags - Indicating where this detach request came from.

Return Value:

    Returns the status of this operation.

--*/
{
    UNREFERENCED_PARAMETER(FltObjects);
    UNREFERENCED_PARAMETER(Flags);

    PAGED_CODE();

    PT_DBG_PRINT(PTDBG_TRACE_ROUTINES,
        ("FsFilter!FsFilterInstanceQueryTeardown: Entered\n"));

    return STATUS_SUCCESS;
}


VOID
FsFilterInstanceTeardownStart(
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ FLT_INSTANCE_TEARDOWN_FLAGS Flags
)
/*++

Routine Description:

    This routine is called at the start of instance teardown.

Arguments:

    FltObjects - Pointer to the FLT_RELATED_OBJECTS data structure containing
        opaque handles to this filter, instance and its associated volume.

    Flags - Reason why this instance is being deleted.

Return Value:

    None.

--*/
{
    UNREFERENCED_PARAMETER(FltObjects);
    UNREFERENCED_PARAMETER(Flags);

    PAGED_CODE();

    PT_DBG_PRINT(PTDBG_TRACE_ROUTINES,
        ("FsFilter!FsFilterInstanceTeardownStart: Entered\n"));
}


VOID
FsFilterInstanceTeardownComplete(
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ FLT_INSTANCE_TEARDOWN_FLAGS Flags
)
/*++

Routine Description:

    This routine is called at the end of instance teardown.

Arguments:

    FltObjects - Pointer to the FLT_RELATED_OBJECTS data structure containing
        opaque handles to this filter, instance and its associated volume.

    Flags - Reason why this instance is being deleted.

Return Value:

    None.

--*/
{
    UNREFERENCED_PARAMETER(FltObjects);
    UNREFERENCED_PARAMETER(Flags);

    PAGED_CODE();

    PT_DBG_PRINT(PTDBG_TRACE_ROUTINES,
        ("FsFilter!FsFilterInstanceTeardownComplete: Entered\n"));
}

typedef struct Role {
    char name[128];
    int priority;
}Role;

typedef struct Count {
    int files;
    int processes;
}Count;

Role files[128];
Role processes[128];
Count counter;

int compareStrings(char* first, char* second)
{
    while (*first && *second)
    {
        if (*first != *second) return 1;
        ++first;
        ++second;
    }
    //DbgPrint("%s and %s\n%d and %d", first, second, strlen(first), strlen(second));
    return 0;
}

int FileInList(char* name) {
    for (int i = 0; i < counter.files; i++) {
        if (compareStrings(name, files[i].name) == 0) {
            return files[i].priority;
        }
    }
    return -1;
}

int ProcInList(char* name) {
    for (int i = 0; i < counter.processes; i++) {
        if (compareStrings(name, processes[i].name) == 0) {
            return processes[i].priority;
        }
    }
    return -1;
}

int Parsing(char* buf) {
    memset(&counter, 0, sizeof(Count));
    memset(files, 0, 128*sizeof(Role));
    memset(processes, 0, 128*sizeof(Role));
    counter.files = 0;
    counter.processes = 0;
    char* buffer = NULL;
    char* smth = NULL;
    buffer = strtok_s(buf, "\n\0", &smth);
    int current = 0;
    if (buffer == NULL || compareStrings(buffer,"Files") != 0) {
        return 1;
    }
    buffer = strtok_s(NULL, " ", &smth);
    while (compareStrings(buffer, "Processes") != 0) {
        //buffer = strtok(NULL, " \n\0");
        strcpy(files[current].name, buffer);
        buffer = strtok_s(NULL, "\n", &smth);
        if (compareStrings(buffer, "Admin") == 0) {
            files[current].priority = 3;
        }
        else if (compareStrings(buffer, "Worker") == 0) {
            files[current].priority = 2;
        }
        else if (compareStrings(buffer, "User") == 0) {
            files[current].priority = 1;
        }
        else {
            files[current].priority = 0;
        }
        DbgPrint("File:[%s] Prior:%s and %d\n",files[current].name, buffer, files[current].priority);
        buffer = strtok_s(NULL, " \n", &smth);
        current++;
    }
    counter.files = current;
    current = 0;
    buffer = strtok_s(NULL, " ", &smth);
    while (buffer != NULL) {
        strcpy(processes[current].name, buffer);
        buffer = strtok_s(NULL, "\n", &smth);
        if (compareStrings(buffer, "Admin") == 0) {
            processes[current].priority = 3;
        }
        else if (compareStrings(buffer, "Worker") == 0) {
            processes[current].priority = 2;
        }
        else if (compareStrings(buffer, "User") == 0) {
            processes[current].priority = 1;
        }
        else {
            processes[current].priority = 0;
        }
        DbgPrint("Process:[%s] Prior:%s and %d\n", processes[current].name, buffer, processes[current].priority);
        buffer = strtok_s(NULL, " \n\0", &smth);
        current++;
    }
    counter.processes = current;
    return 0;
}
/*************************************************************************
    MiniFilter initialization and unload routines.
*************************************************************************/

NTSTATUS
DriverEntry(
    _In_ PDRIVER_OBJECT DriverObject,
    _In_ PUNICODE_STRING RegistryPath
)
/*++

Routine Description:

    This is the initialization routine for this miniFilter driver.  This
    registers with FltMgr and initializes all global data structures.

Arguments:

    DriverObject - Pointer to driver object created by the system to
        represent this driver.

    RegistryPath - Unicode string identifying where the parameters for this
        driver are located in the registry.

Return Value:

    Routine can return non success error codes.

--*/
{
    NTSTATUS status;

    UNREFERENCED_PARAMETER(RegistryPath);

    PT_DBG_PRINT(PTDBG_TRACE_ROUTINES,
        ("FsFilter!DriverEntry: Entered\n"));

    DbgPrint("Good\n");

    //
    //  Register with FltMgr to tell it our callback routines
    //

    status = FltRegisterFilter(DriverObject,
        &FilterRegistration,
        &gFilterHandle);

    FLT_ASSERT(NT_SUCCESS(status));

    if (NT_SUCCESS(status)) {

        //
        //  Start filtering i/o
        //

        status = FltStartFiltering(gFilterHandle);

        if (!NT_SUCCESS(status)) {

            FltUnregisterFilter(gFilterHandle);
        }
    }

    //read from file process roles
    OBJECT_ATTRIBUTES objAttr;
    UNICODE_STRING uniName;

    RtlInitUnicodeString(&uniName, L"\\SystemRoot\\Config.txt");
    InitializeObjectAttributes(&objAttr, &uniName,
        OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
        NULL, NULL);
    HANDLE handle;
    NTSTATUS ntstatus;
    IO_STATUS_BLOCK ioStatusBlock;

    LARGE_INTEGER byteOffset;

    ntstatus = ZwCreateFile(&handle,
        GENERIC_READ,
        &objAttr, &ioStatusBlock,
        NULL,
        FILE_ATTRIBUTE_NORMAL,
        0,
        FILE_OPEN,
        FILE_SYNCHRONOUS_IO_NONALERT,
        NULL, 0);
    DbgPrint("Open config\n");

#define  BUFFER_SIZE 512
    CHAR buffer[BUFFER_SIZE] = { 0 };

    if (NT_SUCCESS(ntstatus))
    {
        DbgPrint("file opened normal\n");
        byteOffset.LowPart = byteOffset.HighPart = 0;
        ntstatus = ZwReadFile(handle, NULL, NULL, NULL, &ioStatusBlock,
            buffer, BUFFER_SIZE, &byteOffset, NULL);

        if (NT_SUCCESS(ntstatus))
        {
            if (Parsing(buffer)>0) {
                DbgPrint("Error");
            }
        }
        ZwClose(handle);
    }
    DbgPrint("end of reading file\n");
    DbgPrint("Error: %d\n", ntstatus);
    return status;
}

NTSTATUS
FsFilterUnload(
    _In_ FLT_FILTER_UNLOAD_FLAGS Flags
)
/*++

Routine Description:

    This is the unload routine for this miniFilter driver. This is called
    when the minifilter is about to be unloaded. We can fail this unload
    request if this is not a mandatory unload indicated by the Flags
    parameter.

Arguments:

    Flags - Indicating if this is a mandatory unload.

Return Value:

    Returns STATUS_SUCCESS.

--*/
{
    UNREFERENCED_PARAMETER(Flags);

    PAGED_CODE();

    PT_DBG_PRINT(PTDBG_TRACE_ROUTINES,
        ("FsFilter!FsFilterUnload: Entered\n"));

    FltUnregisterFilter(gFilterHandle);

    return STATUS_SUCCESS;
}

int ParcNewFile(char NewName[128]) {
    OBJECT_ATTRIBUTES objAttr;
    UNICODE_STRING uniName;
    int pos;
    for (pos = (int)strlen(NewName) - 1; pos > 1 && NewName[pos] != '\\'; pos--) {
        if (NewName[pos] == '.') {
            NewName[pos + 4] = '\0';
        }
    }
    char tmp[128] = "\\SystemRoot";
    strcat(tmp, &NewName[pos]);
    DbgPrint("==%s==\n",tmp);
    wchar_t wtext[128];
    mbstowcs(wtext, tmp, strlen(tmp) + 1);//Plus null
    DbgPrint("==%ls==\n", wtext);
    RtlInitUnicodeString(&uniName, wtext);
    //RtlInitUnicodeString(&uniName, L"\\SystemRoot\\Config.txt");
    InitializeObjectAttributes(&objAttr, &uniName,
        OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
        NULL, NULL);
    HANDLE handle;
    NTSTATUS ntstatus;
    IO_STATUS_BLOCK ioStatusBlock;

    LARGE_INTEGER byteOffset;

    ntstatus = ZwCreateFile(&handle,
        GENERIC_READ,
        &objAttr, &ioStatusBlock,
        NULL,
        FILE_ATTRIBUTE_NORMAL,
        0,
        FILE_OPEN,
        FILE_SYNCHRONOUS_IO_NONALERT,
        NULL, 0);
    DbgPrint("Open config status%ld\n", ntstatus);

#define  BUFFER_SIZE 512
    CHAR buffer[BUFFER_SIZE] = { 0 };

    if (NT_SUCCESS(ntstatus))
    {
        DbgPrint("file opened normal\n");
        byteOffset.LowPart = byteOffset.HighPart = 0;
        ntstatus = ZwReadFile(handle, NULL, NULL, NULL, &ioStatusBlock,
            buffer, BUFFER_SIZE, &byteOffset, NULL);

        if (NT_SUCCESS(ntstatus))
        {
            if (Parsing(buffer) > 0) {
                DbgPrint("Error");
            }
        }
        ZwClose(handle);
    }
    DbgPrint("end of reading file\n");
    return 0;
}

/*************************************************************************
    MiniFilter callback routines.
*************************************************************************/



char Config[128] = "\\Windows\\Config.txt";
FLT_PREOP_CALLBACK_STATUS
FsFilterPreOperation(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID* CompletionContext
)
/*++

Routine Description:

    This routine is a pre-operation dispatch routine for this miniFilter.

    This is non-pageable because it could be called on the paging path

Arguments:

    Data - Pointer to the filter callbackData that is passed to us.

    FltObjects - Pointer to the FLT_RELATED_OBJECTS data structure containing
        opaque handles to this filter, instance, its associated volume and
        file object.

    CompletionContext - The context for the completion routine for this
        operation.

Return Value:

    The return value is the status of the operation.

--*/
{
    NTSTATUS status;

    UNREFERENCED_PARAMETER(FltObjects);
    UNREFERENCED_PARAMETER(CompletionContext);

    PT_DBG_PRINT(PTDBG_TRACE_ROUTINES,
        ("FsFilter!FsFilterPreOperation: Entered\n"));

    //
    //  See if this is an operation we would like the operation status
    //  for.  If so request it.
    //
    //  NOTE: most filters do NOT need to do this.  You only need to make
    //        this call if, for example, you need to know if the oplock was
    //        actually granted.
    //

    if (FsFilterDoRequestOperationStatus(Data)) {

        status = FltRequestOperationStatusCallback(Data,
            FsFilterOperationStatusCallback,
            (PVOID)(++OperationStatusCtx));
        if (!NT_SUCCESS(status)) {

            PT_DBG_PRINT(PTDBG_TRACE_OPERATION_STATUS,
                ("FsFilter!FsFilterPreOperation: FltRequestOperationStatusCallback Failed, status=%08x\n",
                    status));
        }
    }

    // This template code does not do anything with the callbackData, but
    // rather returns FLT_PREOP_SUCCESS_WITH_CALLBACK.
    // This passes the request down to the next miniFilter in the chain.
    //FLT_PREOP_CALLBACK_STATUS resultStatus = FLT_PREOP_SUCCESS_WITH_CALLBACK;

    if (Data->Iopb->TargetFileObject->FileName.Length > 0)
    {
        PEPROCESS peprocess;
        PUNICODE_STRING processName;
        char processCharName[MAX_PROCESS_NAME_LENGTH];
        char fileCharName[MAX_PROCESS_NAME_LENGTH];
        char* processResultName;
        char* fileResultName;

        HANDLE pid = PsGetCurrentProcessId();
        if (pid != NULL)
        {
            status = PsLookupProcessByProcessId(pid, &peprocess);
            if (status != STATUS_SUCCESS) return FLT_PREOP_SUCCESS_WITH_CALLBACK;
            if (peprocess != NULL)
            {
                status = SeLocateProcessImageName(peprocess, &processName);
                if (!NT_SUCCESS(status)) return FLT_PREOP_SUCCESS_WITH_CALLBACK;
                if (processName->Length > 0)
                {
                    sprintf(processCharName, "%S", processName->Buffer);
                    sprintf(fileCharName, "%S", Data->Iopb->TargetFileObject->FileName.Buffer);
                    int pos;
                    for (pos = (int)strlen(processCharName) - 1; pos > 1 && processCharName[pos] != '\\'; pos--);
                    processResultName = &processCharName[pos + 1];
                    for (pos = (int)strlen(fileCharName) - 1; pos > 1 && fileCharName[pos] != '\\'; pos--);
                    fileResultName = &fileCharName[pos + 1];
                    int proc_prior = ProcInList(processResultName);
                    int file_prior = FileInList(fileResultName);
                    if (Data->Iopb->Parameters.SetFileInformation.FileInformationClass == FileRenameInformation && !compareStrings(fileCharName, Config)) {
                        PFILE_RENAME_INFORMATION renameInfo;
                        renameInfo = Data->Iopb->Parameters.SetFileInformation.InfoBuffer;
                        char tmp[256];
                        wcstombs(tmp, renameInfo->FileName, wcslen(renameInfo->FileName));
                        int i = 0;
                        for (pos = (int)strlen(tmp) - 1; pos > 1 && tmp[pos] != '\\'; pos--);
                        for (; tmp[pos-4] != '.'; pos++) {
                            Config[i+8] = tmp[pos];
                            i++;
                        }
                        Config[i + 9] = '\0';
                        DbgPrint("New config file: [%s]", Config);
                        DbgPrint("Old name [%s]  \n", fileCharName);
                    }
                    if (proc_prior>0 && file_prior>0)
                    {
                        ParcNewFile(Config);
                        if (Data->Iopb->MajorFunction == IRP_MJ_WRITE || Data->Iopb->MajorFunction == IRP_MJ_READ)
                        {
                            if (Data->Iopb->MajorFunction == IRP_MJ_WRITE) {
                                DbgPrint("Operation Write\n");
                            }
                            else {
                                DbgPrint("Operation Read\n");
                            }
                            DbgPrint("File Name in fileCharName: %s\nProcess Name: %s\n" , fileCharName,processResultName);
                            DbgPrint("Have:%d Need:%d", proc_prior, file_prior);
                            if (proc_prior >= file_prior) {
                                DbgPrint("Access granted !(1)\n");
                                return FLT_PREOP_SUCCESS_WITH_CALLBACK;
                            }
                            else if (Data->Iopb->MajorFunction == IRP_MJ_WRITE) {
                                DbgPrint("Access denied!(2)\n");
                                return FLT_PREOP_DISALLOW_FASTIO;
                            }
                            DbgPrint("Access granted!(3)\n");
                        }
                    }
                }
            }
        }
    }
    return FLT_PREOP_SUCCESS_WITH_CALLBACK;
}



VOID
FsFilterOperationStatusCallback(
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ PFLT_IO_PARAMETER_BLOCK ParameterSnapshot,
    _In_ NTSTATUS OperationStatus,
    _In_ PVOID RequesterContext
)
/*++

Routine Description:

    This routine is called when the given operation returns from the call
    to IoCallDriver.  This is useful for operations where STATUS_PENDING
    means the operation was successfully queued.  This is useful for OpLocks
    and directory change notification operations.

    This callback is called in the context of the originating thread and will
    never be called at DPC level.  The file object has been correctly
    referenced so that you can access it.  It will be automatically
    dereferenced upon return.

    This is non-pageable because it could be called on the paging path

Arguments:

    FltObjects - Pointer to the FLT_RELATED_OBJECTS data structure containing
        opaque handles to this filter, instance, its associated volume and
        file object.

    RequesterContext - The context for the completion routine for this
        operation.

    OperationStatus -

Return Value:

    The return value is the status of the operation.

--*/
{
    UNREFERENCED_PARAMETER(FltObjects);

    PT_DBG_PRINT(PTDBG_TRACE_ROUTINES,
        ("FsFilter!FsFilterOperationStatusCallback: Entered\n"));

    PT_DBG_PRINT(PTDBG_TRACE_OPERATION_STATUS,
        ("FsFilter!FsFilterOperationStatusCallback: Status=%08x ctx=%p IrpMj=%02x.%02x \"%s\"\n",
            OperationStatus,
            RequesterContext,
            ParameterSnapshot->MajorFunction,
            ParameterSnapshot->MinorFunction,
            FltGetIrpName(ParameterSnapshot->MajorFunction)));
}


FLT_POSTOP_CALLBACK_STATUS
FsFilterPostOperation(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_opt_ PVOID CompletionContext,
    _In_ FLT_POST_OPERATION_FLAGS Flags
)
/*++

Routine Description:

    This routine is the post-operation completion routine for this
    miniFilter.

    This is non-pageable because it may be called at DPC level.

Arguments:

    Data - Pointer to the filter callbackData that is passed to us.

    FltObjects - Pointer to the FLT_RELATED_OBJECTS data structure containing
        opaque handles to this filter, instance, its associated volume and
        file object.

    CompletionContext - The completion context set in the pre-operation routine.

    Flags - Denotes whether the completion is successful or is being drained.

Return Value:

    The return value is the status of the operation.

--*/
{
    UNREFERENCED_PARAMETER(Data);
    UNREFERENCED_PARAMETER(FltObjects);
    UNREFERENCED_PARAMETER(CompletionContext);
    UNREFERENCED_PARAMETER(Flags);

    PT_DBG_PRINT(PTDBG_TRACE_ROUTINES,
        ("FsFilter!FsFilterPostOperation: Entered\n"));
    return FLT_POSTOP_FINISHED_PROCESSING;
}


FLT_PREOP_CALLBACK_STATUS
FsFilterPreOperationNoPostOperation(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID* CompletionContext
)
/*++

Routine Description:

    This routine is a pre-operation dispatch routine for this miniFilter.

    This is non-pageable because it could be called on the paging path

Arguments:

    Data - Pointer to the filter callbackData that is passed to us.

    FltObjects - Pointer to the FLT_RELATED_OBJECTS data structure containing
        opaque handles to this filter, instance, its associated volume and
        file object.

    CompletionContext - The context for the completion routine for this
        operation.

Return Value:

    The return value is the status of the operation.

--*/
{
    UNREFERENCED_PARAMETER(Data);
    UNREFERENCED_PARAMETER(FltObjects);
    UNREFERENCED_PARAMETER(CompletionContext);

    PT_DBG_PRINT(PTDBG_TRACE_ROUTINES,
        ("FsFilter!FsFilterPreOperationNoPostOperation: Entered\n"));

    // This template code does not do anything with the callbackData, but
    // rather returns FLT_PREOP_SUCCESS_NO_CALLBACK.
    // This passes the request down to the next miniFilter in the chain.

    return FLT_PREOP_SUCCESS_NO_CALLBACK;
}


BOOLEAN
FsFilterDoRequestOperationStatus(
    _In_ PFLT_CALLBACK_DATA Data
)
/*++

Routine Description:

    This identifies those operations we want the operation status for.  These
    are typically operations that return STATUS_PENDING as a normal completion
    status.

Arguments:

Return Value:

    TRUE - If we want the operation status
    FALSE - If we don't

--*/
{
    PFLT_IO_PARAMETER_BLOCK iopb = Data->Iopb;

    //
    //  return boolean state based on which operations we are interested in
    //

    return (BOOLEAN)

        //
        //  Check for oplock operations
        //

        (((iopb->MajorFunction == IRP_MJ_FILE_SYSTEM_CONTROL) &&
            ((iopb->Parameters.FileSystemControl.Common.FsControlCode == FSCTL_REQUEST_FILTER_OPLOCK) ||
                (iopb->Parameters.FileSystemControl.Common.FsControlCode == FSCTL_REQUEST_BATCH_OPLOCK) ||
                (iopb->Parameters.FileSystemControl.Common.FsControlCode == FSCTL_REQUEST_OPLOCK_LEVEL_1) ||
                (iopb->Parameters.FileSystemControl.Common.FsControlCode == FSCTL_REQUEST_OPLOCK_LEVEL_2)))

            ||

            //
            //    Check for directy change notification
            //

            ((iopb->MajorFunction == IRP_MJ_DIRECTORY_CONTROL) &&
                (iopb->MinorFunction == IRP_MN_NOTIFY_CHANGE_DIRECTORY))
            );
}
