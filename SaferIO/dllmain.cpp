//  SPDX-License-Identifier: LGPL-2.1-or-later
//
//  SaferIO Library - Simple library for IO access
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
#include "global.h"
#include "sup.h"
#include "resource.h"

EXTERN_C IMAGE_DOS_HEADER __ImageBase;
#define HINST_THISCOMPONENT ((HINSTANCE)&__ImageBase)

HANDLE g_DeviceHandle{};

WCHAR g_AppName[MAX_PATH]{};
WCHAR g_TempFileName[MAX_PATH + 1]{};

extern "C" BOOL APIENTRY DllEntry(
  HMODULE Module,
  DWORD Reason,
  LPVOID Reserved
)
{
  switch (Reason)
  {
  case DLL_PROCESS_ATTACH:
  case DLL_THREAD_ATTACH:
  case DLL_THREAD_DETACH:
    break;

  case DLL_PROCESS_DETACH:
    DrvUninitialize(g_AppName);
    break;
  }
  return TRUE;
}

BOOL APIENTRY DllMain(
  HMODULE Module,
  DWORD Reason,
  LPVOID Reserved
)
{
  return DllEntry(Module, Reason, Reserved);
}

USHORT GetNativeArchitecture()
{
  using LPFN_ISWOW64PROCESS2 = BOOL(WINAPI*)(HANDLE, PUSHORT, PUSHORT);

  const auto Kernel32 = GetModuleHandleW(L"kernel32");
  const auto FnIsWow64Process2 = Kernel32 ? (LPFN_ISWOW64PROCESS2)GetProcAddress(Kernel32, "IsWow64Process2") : nullptr;
  USHORT ProcessMachine = 0;
  USHORT NativeMachine = 0;

  // Apparently IsWow64Process2 can fail somehow
  if (FnIsWow64Process2 && FnIsWow64Process2(GetCurrentProcess(), &ProcessMachine, &NativeMachine))
    return NativeMachine;

  SYSTEM_INFO SystemInfo;
  // On 64 bit processors that aren't x64 or IA64, GetNativeSystemInfo behaves as GetSystemInfo
  GetNativeSystemInfo(&SystemInfo);
  switch (SystemInfo.wProcessorArchitecture)
  {
  case PROCESSOR_ARCHITECTURE_AMD64:
    return (USHORT)IMAGE_FILE_MACHINE_AMD64;
  case PROCESSOR_ARCHITECTURE_ARM:
    return (USHORT)IMAGE_FILE_MACHINE_ARM;
  case PROCESSOR_ARCHITECTURE_ARM64: // according to docs this could never happen
    return (USHORT)IMAGE_FILE_MACHINE_ARM64;
  case PROCESSOR_ARCHITECTURE_IA64:
    return (USHORT)IMAGE_FILE_MACHINE_IA64;
  case PROCESSOR_ARCHITECTURE_INTEL:
    return (USHORT)IMAGE_FILE_MACHINE_I386;
  default:
    break;
  }

  // I wonder why does IsWow64Process exist when GetNativeSystemInfo can provide same and more, plus it cannot fail
  // either unlike IsWow64Process which apparently can do so.

  return (USHORT)IMAGE_FILE_MACHINE_UNKNOWN;
}

NTSTATUS GetDriverData(PVOID* Buffer, ULONG* Size)
{
  *Buffer = nullptr;
  *Size = 0;

  const auto Architecture = GetNativeArchitecture();

  ULONG ResourceId = 0;

  if (Architecture == IMAGE_FILE_MACHINE_I386)
    ResourceId = IDR_DRIVER_X86;
  else if (Architecture == IMAGE_FILE_MACHINE_AMD64)
    ResourceId = IDR_DRIVER_X64;
  else
    return STATUS_NOT_SUPPORTED;

  return supQueryResourceData(ResourceId, HINST_THISCOMPONENT, Buffer, Size);
}

NTSTATUS DrvpLoadDriver(PCWSTR Name)
{
  NTSTATUS Status = STATUS_SUCCESS;
  HANDLE File{};
  PSECURITY_DESCRIPTOR AdminSD{};
  PACL DefaultACL{};
  PVOID DriverBuffer{};
  ULONG DriverSize{};

  Status = GetDriverData(&DriverBuffer, &DriverSize);
  if (!NT_SUCCESS(Status))
    return Status;

  WCHAR TempPath[MAX_PATH + 1]{};
  GetTempPathW((DWORD)std::size(TempPath), TempPath);

  WCHAR TempFileName[MAX_PATH + 1]{};
  GetTempFileNameW(TempPath, L"SIO", 0, TempFileName);

  supWriteBufferToFile(
    TempFileName,
    DriverBuffer,
    DriverSize,
    TRUE,
    &Status,
    WRITE_DAC,
    &File
  );
  
  if (NT_SUCCESS(Status))
  {
    Status = supCreateSystemAdminAccessSD(&AdminSD, &DefaultACL);
    if (NT_SUCCESS(Status))
    {
      Status = NtSetSecurityObject(
        File,
        DACL_SECURITY_INFORMATION,
        AdminSD
      );
      
      if (NT_SUCCESS(Status))
      {
        wcscpy_s(g_TempFileName, TempFileName);

        NtClose(File);
        File = nullptr;

        Status = supEnablePrivilege(SE_LOAD_DRIVER_PRIVILEGE, TRUE);
        if (NT_SUCCESS(Status))
        {
          Status = supLoadDriver(Name, TempFileName, FALSE);
          supMarkForDelete(TempFileName);
        }
      }
    }
  }

  if (File)
    NtClose(File);

  if (g_TempFileName[0])
    supMarkForDelete(g_TempFileName);

  if (DefaultACL)
    supHeapFree(DefaultACL);

  if (AdminSD)
    supHeapFree(AdminSD);

  return Status;
}

SAFERIO_EXPORT(NTSTATUS) DrvInitialize(PCWSTR Name)
{
  NTSTATUS Status = STATUS_SUCCESS;

  if (!Name || !*Name)
    return STATUS_INVALID_PARAMETER;

  if (g_DeviceHandle)
    return STATUS_ALREADY_INITIALIZED;

  wcscpy_s(g_AppName, Name);

  Status = supOpenDriver(Name, GENERIC_WRITE | GENERIC_READ, &g_DeviceHandle);

  if (Status == STATUS_OBJECT_NAME_NOT_FOUND)
  {
    Status = DrvpLoadDriver(Name);
    if (NT_SUCCESS(Status))
    {
      Status = supOpenDriver(Name, GENERIC_WRITE | GENERIC_READ, &g_DeviceHandle);
    }
  }
  
  return Status;
}

SAFERIO_EXPORT(NTSTATUS) DrvUninitialize(PCWSTR Name)
{
  NTSTATUS Status = STATUS_SUCCESS;
  
  if (!Name || !*Name)
    return STATUS_INVALID_PARAMETER;

  if (0 != wcscmp(Name, g_AppName))
    return STATUS_INVALID_PARAMETER;

  if (!g_DeviceHandle)
    return STATUS_SUCCESS;

  ULONG RefCount{};
  Status = DrvGetRefCount(RefCount);
  if (!NT_SUCCESS(Status))
    return Status;

  NtClose(g_DeviceHandle);
  g_DeviceHandle = nullptr;

  if (RefCount > 1)
    return STATUS_SUCCESS;
  
  Status = supEnablePrivilege(SE_LOAD_DRIVER_PRIVILEGE, TRUE);
  if (!NT_SUCCESS(Status))
    return Status;

  Status = supUnloadDriver(Name, TRUE);

  if (g_TempFileName[0])
    supMarkForDelete(g_TempFileName);

  return Status;
}

NTSTATUS IoCtl(ULONG Code, PVOID InputBuffer, ULONG InputBufferLength, PVOID OutputBuffer, ULONG OutputBufferLength)
{
  return supCallDriver(
    g_DeviceHandle,
    Code,
    InputBuffer,
    InputBufferLength,
    OutputBuffer,
    OutputBufferLength
  );
}