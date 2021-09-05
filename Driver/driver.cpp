//  SPDX-License-Identifier: LGPL-2.1-or-later
//
//  We use LGPL 2.1 here since it lacks anti-tivoization clause which would
//  prevent Microsoft from WHQL signing it.
//
//  SaferIO Driver - Simple giveio-style driver with secure access
//  Copyright (C) 2021  namazso <admin@namazso.eu>
//
//  This library is free software; you can redistribute it and/or
//  modify it under the terms of the GNU Lesser General Public
//  License as published by the Free Software Foundation; either
//  version 2.1 of the License, or (at your option) any later version.
//
//  This library is distributed in the hope that it will be useful,
//  but WITHOUT ANY WARRANTY; without even the implied warranty of
//  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
//  Lesser General Public License for more details.
//
//  You should have received a copy of the GNU Lesser General Public
//  License along with this library; if not, write to the Free Software
//  Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
#include <ntddk.h>
#include <wdm.h>
#include <wdmsec.h>
#include <intrin.h>

#include "ioctl.h"

#define NT_DEVICE_BASE_PATH      L"\\Device\\"
#define DOS_DEVICE_BASE_PATH     L"\\DosDevices\\"

#define ALLOC_TAG 'dOIS'

const UNICODE_STRING PHYSICAL_MEMORY = RTL_CONSTANT_STRING(L"\\Device\\PhysicalMemory");

EXTERN_C DRIVER_INITIALIZE DriverEntry;

_Dispatch_type_(IRP_MJ_CREATE)
DRIVER_DISPATCH IrpCreate;

_Dispatch_type_(IRP_MJ_CLOSE)
DRIVER_DISPATCH IrpClose;

_Dispatch_type_(IRP_MJ_DEVICE_CONTROL)
DRIVER_DISPATCH IrpDeviceControl;

DRIVER_UNLOAD DriverUnload;

UNICODE_STRING g_NtDevicePath{};
UNICODE_STRING g_DosDevicePath{};
PDEVICE_OBJECT g_DeviceObject{};
LONG g_RefCount{};

NTSTATUS DriverEntry(
  _In_ PDRIVER_OBJECT DriverObject,
  _In_ PUNICODE_STRING RegistryPath
)
{
  UNREFERENCED_PARAMETER(RegistryPath);

  NTSTATUS Status = STATUS_SUCCESS;

  const auto& DriverName = DriverObject->DriverName;

  const auto NtDevicePathSize = DriverName.Length + sizeof(NT_DEVICE_BASE_PATH) + sizeof(WCHAR);
  const auto NtDevicePathBuffer = (PWSTR)ExAllocatePoolZero(NonPagedPool, NtDevicePathSize, ALLOC_TAG);

  if (NtDevicePathBuffer)
  {
    const auto DosDevicePathSize = DriverName.Length + sizeof(DOS_DEVICE_BASE_PATH) + sizeof(WCHAR);
    const auto DosDevicePathBuffer = (PWSTR)ExAllocatePoolZero(NonPagedPool, NtDevicePathSize, ALLOC_TAG);

    if (DosDevicePathBuffer)
    {
      wcscpy(NtDevicePathBuffer, NT_DEVICE_BASE_PATH);
      wcscpy(DosDevicePathBuffer, DOS_DEVICE_BASE_PATH);

      g_NtDevicePath = {
        sizeof(NT_DEVICE_BASE_PATH) - sizeof(WCHAR),
        (USHORT)NtDevicePathSize,
        NtDevicePathBuffer
      };
      g_DosDevicePath = {
        sizeof(DOS_DEVICE_BASE_PATH) - sizeof(WCHAR),
        (USHORT)DosDevicePathSize,
        DosDevicePathBuffer
      };

      RtlAppendUnicodeStringToString(&g_NtDevicePath, &DriverName);
      RtlAppendUnicodeStringToString(&g_DosDevicePath, &DriverName);

      Status = WdmlibIoCreateDeviceSecure(
        DriverObject,
        0,
        &g_NtDevicePath,
        FILE_DEVICE_UNKNOWN,
        FILE_DEVICE_SECURE_OPEN,
        FALSE,
        &SDDL_DEVOBJ_SYS_ALL_ADM_ALL,
        nullptr,
        &g_DeviceObject
      );

      if (NT_SUCCESS(Status))
      {
        Status = IoCreateSymbolicLink(&g_DosDevicePath, &g_NtDevicePath);

        if (NT_SUCCESS(Status))
        {
          DriverObject->MajorFunction[IRP_MJ_CREATE] = IrpCreate;
          DriverObject->MajorFunction[IRP_MJ_CLOSE] = IrpClose;
          DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = IrpDeviceControl;

          DriverObject->DriverUnload = DriverUnload;

          DriverObject->Flags &= ~DO_DEVICE_INITIALIZING;

          return Status;
        }

        IoDeleteDevice(g_DeviceObject);
      }

      ExFreePool(DosDevicePathBuffer);
    }
    else
    {
      Status = STATUS_NO_MEMORY;
    }

    ExFreePool(NtDevicePathBuffer);
  }
  else
  {
    Status = STATUS_NO_MEMORY;
  }

  return Status;
}

VOID DriverUnload(
  _In_ PDRIVER_OBJECT DriverObject
)
{
  UNREFERENCED_PARAMETER(DriverObject);

  IoDeleteSymbolicLink(&g_DosDevicePath);
  IoDeleteDevice(g_DeviceObject);
  RtlFreeUnicodeString(&g_NtDevicePath);
  RtlFreeUnicodeString(&g_DosDevicePath);
}

NTSTATUS IrpCreate(
  PDEVICE_OBJECT DeviceObject,
  PIRP Irp
)
{
  UNREFERENCED_PARAMETER(DeviceObject);

  OBJECT_ATTRIBUTES ObjectAttributes;
  InitializeObjectAttributes(
    &ObjectAttributes,
    const_cast<PUNICODE_STRING>(&PHYSICAL_MEMORY),
    OBJ_CASE_INSENSITIVE,
    (HANDLE)nullptr,
    (PSECURITY_DESCRIPTOR)nullptr
  );

  HANDLE PhysicalMemory{};
  const auto Status = ZwOpenSection(
    &PhysicalMemory,
    SECTION_ALL_ACCESS,
    &ObjectAttributes
  );

  if (NT_SUCCESS(Status))
  {
    const auto Stack = IoGetCurrentIrpStackLocation(Irp);
    Stack->FileObject->FsContext = (PVOID)PhysicalMemory;

    InterlockedIncrement(&g_RefCount);
  }
  
  Irp->IoStatus.Status = Status;
  Irp->IoStatus.Information = 0;

  IoCompleteRequest(Irp, IO_NO_INCREMENT);

  return Status;
}

NTSTATUS IrpClose(
  PDEVICE_OBJECT DeviceObject,
  PIRP Irp
)
{
  UNREFERENCED_PARAMETER(DeviceObject);

  const auto Stack = IoGetCurrentIrpStackLocation(Irp);
  auto& Context = Stack->FileObject->FsContext;
  const auto PhysicalMemory = (HANDLE)Context;

  if (PhysicalMemory)
  {
    ZwClose(PhysicalMemory);
    Context = nullptr;
  }

  InterlockedDecrement(&g_RefCount);
  
  Irp->IoStatus.Status = STATUS_SUCCESS;
  Irp->IoStatus.Information = 0;

  IoCompleteRequest(Irp, IO_NO_INCREMENT);

  return STATUS_SUCCESS;
}

using IOCTL_HANDLER_FN = NTSTATUS(*)(PVOID Context, ULONG Code, PVOID Buffer, ULONG InSize, ULONG OutSize);

struct IOCTL_HANDLER
{
  ULONG Code;
  ULONG InSize;
  ULONG OutSize;

  ULONG InChecked : 1;
  ULONG OutChecked : 1;
  ULONG Reserved : 30;

  IOCTL_HANDLER_FN Handler;
};

template <typename T>
NTSTATUS IoCtlPhysicalMemoryRead(PVOID, ULONG, PVOID Buffer, ULONG, ULONG)
{
  const auto Virtual = MmGetVirtualForPhysical(*(PPHYSICAL_ADDRESS)Buffer);
  if (!Virtual)
    return STATUS_INVALID_PARAMETER;
  *(T*)Buffer = *(T*)Virtual;
  return STATUS_SUCCESS;
}

template <typename T>
NTSTATUS IoCtlPhysicalMemoryWrite(PVOID, ULONG, PVOID Buffer, ULONG, ULONG)
{
  const auto Virtual = MmGetVirtualForPhysical(*(PPHYSICAL_ADDRESS)Buffer);
  if (!Virtual)
    return STATUS_INVALID_PARAMETER;
  *(T*)Virtual = *(T*)(((PPHYSICAL_ADDRESS)Buffer) + 1);
  return STATUS_SUCCESS;
}

#pragma warning(push)
#pragma warning(disable: 4996)

NTSTATUS PCIConfigRead(const IOCTL_PCI_CONFIG_CMD* Cmd, PVOID Buffer, ULONG Length)
{
  if (Length == 0)
    return STATUS_INVALID_PARAMETER;

  PCI_SLOT_NUMBER Slot{};
  Slot.u.bits.DeviceNumber = Cmd->DeviceNumber;
  Slot.u.bits.FunctionNumber = Cmd->FunctionNumber;

  USHORT VendorId{};
  auto Result = HalGetBusDataByOffset(
    PCIConfiguration,
    Cmd->BusNumber,
    Slot.u.AsULONG,
    &VendorId,
    0,
    sizeof(VendorId)
  );

  if (Result == 0)
    return STATUS_NOT_FOUND;

  if (Result == 2 && VendorId == PCI_INVALID_VENDORID)
    return STATUS_DEVICE_DOES_NOT_EXIST;
  
  Result = HalGetBusDataByOffset(
    PCIConfiguration,
    Cmd->BusNumber,
    Slot.u.AsULONG,
    Buffer,
    Cmd->Offset,
    Length
  );

  if (Result == 0)
    return STATUS_NOT_FOUND;

  if (Result == 2 && Length != 2)
    return STATUS_DEVICE_DOES_NOT_EXIST;

  if (Result != Length)
    return STATUS_UNSUCCESSFUL;

  return STATUS_SUCCESS;
}

NTSTATUS PCIConfigWrite(const IOCTL_PCI_CONFIG_CMD* Cmd, PVOID Buffer, ULONG Length)
{
  if (Length == 0)
    return STATUS_INVALID_PARAMETER;

  PCI_SLOT_NUMBER Slot{};
  Slot.u.bits.DeviceNumber = Cmd->DeviceNumber;
  Slot.u.bits.FunctionNumber = Cmd->FunctionNumber;

  USHORT VendorId{};
  auto Result = HalGetBusDataByOffset(
    PCIConfiguration,
    Cmd->BusNumber,
    Slot.u.AsULONG,
    &VendorId,
    0,
    sizeof(VendorId)
  );

  if (Result == 0)
    return STATUS_NOT_FOUND;

  if (Result == 2 && VendorId == PCI_INVALID_VENDORID)
    return STATUS_DEVICE_DOES_NOT_EXIST;

  Result = HalSetBusDataByOffset(
    PCIConfiguration,
    Cmd->BusNumber,
    Slot.u.AsULONG,
    Buffer,
    Cmd->Offset,
    Length
  );
  
  if (Result != Length)
    return STATUS_UNSUCCESSFUL;

  return STATUS_SUCCESS;
}

#pragma warning(pop)

extern "C" ULONG __fastcall _dell(IOCTL_DELL_SMM_REGS* Registers);

NTSTATUS QueryDellSMM(IOCTL_DELL_SMM_REGS In, IOCTL_DELL_SMM_REGS* Out)
{
  *Out = In;
  const auto Result = _dell(Out);
  return (Result != 0 || (Out->Eax & 0xFFFF) == 0xFFFF || Out->Eax == In.Eax) ? STATUS_UNSUCCESSFUL : STATUS_SUCCESS;
}

NTSTATUS MsrRead(ULONG Index, ULONG64* Value)
{
  NTSTATUS Status = STATUS_SUCCESS;
  __try
  {
    *Value = __readmsr(Index);
  }
  __except (EXCEPTION_EXECUTE_HANDLER)
  {
    Status = GetExceptionCode();
  }
  return Status;
}

NTSTATUS MsrWrite(ULONG Index, ULONG64 Value)
{
  NTSTATUS Status = STATUS_SUCCESS;
  __try
  {
    __writemsr(Index, Value);
  }
  __except (EXCEPTION_EXECUTE_HANDLER)
  {
    Status = GetExceptionCode();
  }
  return Status;
}

const static IOCTL_HANDLER IOCTL_HANDLERS[] = {
  {
    IOCTL_IO_PORT_READ,
    2,
    1,
    1,
    1,
    0,
    (IOCTL_HANDLER_FN)[] (PVOID, ULONG, PVOID Buffer, ULONG, ULONG)
    {
      *(PUCHAR)Buffer = __inbyte(*(PUSHORT)Buffer);
      return STATUS_SUCCESS;
    }
  },
  {
    IOCTL_IO_PORT_READ,
    2,
    2,
    1,
    1,
    0,
    (IOCTL_HANDLER_FN)[](PVOID, ULONG, PVOID Buffer, ULONG, ULONG)
    {
      *(PUSHORT)Buffer = __inword(*(PUSHORT)Buffer);
      return STATUS_SUCCESS;
    }
  },
  {
    IOCTL_IO_PORT_READ,
    2,
    4,
    1,
    1,
    0,
    (IOCTL_HANDLER_FN)[](PVOID, ULONG, PVOID Buffer, ULONG, ULONG)
    {
      *(PULONG)Buffer = __indword(*(PUSHORT)Buffer);
      return STATUS_SUCCESS;
    }
  },
  {
    IOCTL_IO_PORT_WRITE,
    5,
    0,
    1,
    1,
    0,
    (IOCTL_HANDLER_FN)[](PVOID, ULONG, PVOID Buffer, ULONG, ULONG)
    {
      __outbyte(*(PUSHORT)Buffer, *(PUCHAR)(((char*)Buffer) + 4));
      return STATUS_SUCCESS;
    }
  },
  {
    IOCTL_IO_PORT_WRITE,
    6,
    0,
    1,
    1,
    0,
    (IOCTL_HANDLER_FN)[](PVOID, ULONG, PVOID Buffer, ULONG, ULONG)
    {
      __outword(*(PUSHORT)Buffer, *(PUSHORT)(((char*)Buffer) + 4));
      return STATUS_SUCCESS;
    }
  },
  {
    IOCTL_IO_PORT_WRITE,
    8,
    0,
    1,
    1,
    0,
    (IOCTL_HANDLER_FN)[](PVOID, ULONG, PVOID Buffer, ULONG, ULONG)
    {
      __outdword(*(PUSHORT)Buffer, *(PULONG)(((char*)Buffer) + 4));
      return STATUS_SUCCESS;
    }
  },
  {
    IOCTL_MSR_READ,
    4,
    8,
    1,
    1,
    0,
    (IOCTL_HANDLER_FN)[](PVOID, ULONG, PVOID Buffer, ULONG, ULONG)
    {
      ULONG64 Value = 0;
      const auto Status = MsrRead(*(PULONG)Buffer, &Value);
      *(PULONG64)Buffer = Value;
      return Status;
    }
  },
  {
    IOCTL_MSR_WRITE,
    12,
    0,
    1,
    1,
    0,
    (IOCTL_HANDLER_FN)[](PVOID, ULONG, PVOID Buffer, ULONG, ULONG)
    {
      const ULONG Index = *(PULONG)Buffer;
      const ULONG64 Value = *(PULONG64)(((char*)Buffer) + 4);
      return MsrWrite(Index, Value);
    }
  },
  {
    IOCTL_PHYSMEM_MAP,
    12,
    0,
    1,
    0,
    0,
    (IOCTL_HANDLER_FN)[](PVOID Context, ULONG, PVOID Buffer, ULONG, ULONG OutSize)
    {
      if (OutSize != 4 && OutSize != 8)
        return STATUS_INVALID_BUFFER_SIZE;

      if (!Context)
        return STATUS_UNSUCCESSFUL;

      PVOID MappedAddress{};
      LARGE_INTEGER PhysicalAddress{};
      PhysicalAddress.QuadPart = *(PULONG64)Buffer;
      const auto Length = *(PULONG)(((char*)Buffer) + 8);
      SIZE_T ViewSize = Length;

      const auto Status = ZwMapViewOfSection(
        Context,
        NtCurrentProcess(),
        &MappedAddress,
        0L,
        Length,
        &PhysicalAddress,
        &ViewSize,
        ViewShare,
        0,
        PAGE_READWRITE | PAGE_NOCACHE
      );

      if (OutSize == 4)
        *(PULONG)Buffer = (ULONG)(ULONG_PTR)MappedAddress;
      else
        *(PULONG64)Buffer = (ULONG64)(ULONG_PTR)MappedAddress;

      return Status;
    }
  },
  {
    IOCTL_PHYSMEM_UNMAP,
    0,
    0,
    0,
    1,
    0,
    (IOCTL_HANDLER_FN)[](PVOID, ULONG, PVOID Buffer, ULONG InSize, ULONG)
    {
      if (InSize != 4 && InSize != 8)
        return STATUS_INVALID_BUFFER_SIZE;

      const auto MappedAddress = InSize == 4
        ? ((PVOID)(ULONG_PTR)*(PULONG)Buffer)
        : ((PVOID)(ULONG_PTR)*(PULONG64)Buffer);

      if ((ULONG_PTR)MM_HIGHEST_USER_ADDRESS < (ULONG_PTR)MappedAddress)
        return STATUS_INVALID_PARAMETER;

      return ZwUnmapViewOfSection(
        NtCurrentProcess(),
        MappedAddress
      );
    }
  },
  {
    IOCTL_GET_REFCOUNT,
    0,
    4,
    1,
    1,
    0,
    (IOCTL_HANDLER_FN)[](PVOID, ULONG, PVOID Buffer, ULONG, ULONG)
    {
      *(PLONG)Buffer = g_RefCount;
      return STATUS_SUCCESS;
    }
  },
  { IOCTL_PHYSMEM_READ, 8, 1, 1, 1, 0, &IoCtlPhysicalMemoryRead<UCHAR> },
  { IOCTL_PHYSMEM_READ, 8, 2, 1, 1, 0, &IoCtlPhysicalMemoryRead<USHORT> },
  { IOCTL_PHYSMEM_READ, 8, 4, 1, 1, 0, &IoCtlPhysicalMemoryRead<ULONG> },
  { IOCTL_PHYSMEM_READ, 8, 8, 1, 1, 0, &IoCtlPhysicalMemoryRead<ULONG64> },

  { IOCTL_PHYSMEM_WRITE, 9,  1, 1, 1, 0, &IoCtlPhysicalMemoryWrite<UCHAR> },
  { IOCTL_PHYSMEM_WRITE, 10, 2, 1, 1, 0, &IoCtlPhysicalMemoryWrite<USHORT> },
  { IOCTL_PHYSMEM_WRITE, 12, 4, 1, 1, 0, &IoCtlPhysicalMemoryWrite<ULONG> },
  { IOCTL_PHYSMEM_WRITE, 16, 8, 1, 1, 0, &IoCtlPhysicalMemoryWrite<ULONG64> },

  {
    IOCTL_PCI_CONFIG_READ,
    sizeof(IOCTL_PCI_CONFIG_CMD),
    0,
    1,
    0,
    0,
    (IOCTL_HANDLER_FN)[](PVOID, ULONG, PVOID Buffer, ULONG, ULONG OutSize)
    {
      return PCIConfigRead((IOCTL_PCI_CONFIG_CMD*)Buffer, Buffer, OutSize);
    }
  },
  {
    IOCTL_PCI_CONFIG_WRITE,
    0,
    0,
    0,
    1,
    0,
    (IOCTL_HANDLER_FN)[](PVOID, ULONG, PVOID Buffer, ULONG InSize, ULONG)
    {
      if (InSize < sizeof(IOCTL_PCI_CONFIG_CMD) + 1)
        return STATUS_INVALID_BUFFER_SIZE;

      const auto Cmd = (IOCTL_PCI_CONFIG_CMD*)Buffer;
      return PCIConfigRead(Cmd, Cmd + 1, InSize - sizeof(IOCTL_PCI_CONFIG_CMD));
    }
  },
  {
    IOCTL_DELL_SMM,
    sizeof(IOCTL_DELL_SMM_REGS),
    sizeof(IOCTL_DELL_SMM_REGS),
    1,
    1,
    0,
    (IOCTL_HANDLER_FN)[](PVOID, ULONG, PVOID Buffer, ULONG, ULONG)
    {
      return QueryDellSMM(*(IOCTL_DELL_SMM_REGS*)Buffer, (IOCTL_DELL_SMM_REGS*)Buffer);
    }
  },
};

NTSTATUS IrpDeviceControl(
  PDEVICE_OBJECT DeviceObject,
  PIRP Irp
)
{
  UNREFERENCED_PARAMETER(DeviceObject);

  auto Status = STATUS_NOT_IMPLEMENTED;

  const auto Stack = IoGetCurrentIrpStackLocation(Irp);
  auto& Context = Stack->FileObject->FsContext;
  auto& Params = Stack->Parameters.DeviceIoControl;

  const auto Code = Params.IoControlCode;
  const auto Buffer = Irp->AssociatedIrp.SystemBuffer;
  const auto InSize = Params.InputBufferLength;
  const auto OutSize = Params.OutputBufferLength;

  for (const auto& Handler : IOCTL_HANDLERS)
  {
    if (Handler.Code != Code)
      continue;

    // If we find at least one with matching code assume the sizes are invalid
    Status = STATUS_INVALID_BUFFER_SIZE;

    if (Handler.InChecked && Handler.InSize != InSize)
      continue;

    if (Handler.OutChecked && Handler.OutSize != OutSize)
      continue;

    // Found first matching handler
    Status = Handler.Handler(Context, Code, Buffer, InSize, OutSize);
    break;
  }
  
  Irp->IoStatus.Status = Status;
  Irp->IoStatus.Information = NT_SUCCESS(Status) ? OutSize : 0;

  IoCompleteRequest(Irp, IO_NO_INCREMENT);

  return Status;
}
