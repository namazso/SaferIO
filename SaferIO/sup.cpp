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
//
//  Notice for original file from KDU Project:
//
//  Copyright (c) 2020 - 2021 KDU Project
// 
//  Permission is hereby granted, free of charge, to any person obtaining a copy
//  of this software and associated documentation files (the "Software"), to deal
//  in the Software without restriction, including without limitation the rights
//  to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
//  copies of the Software, and to permit persons to whom the Software is
//  furnished to do so, subject to the following conditions:
// 
//  The above copyright notice and this permission notice shall be included in all
//  copies or substantial portions of the Software.
//  
//  TITLE:       SUP.CPP
// 
//  VERSION:     1.11
// 
//  DATE:        14 May 2021
// 
//  Program global support routines.

#include "global.h"
#include "sup.h"

#define NT_REG_PREP             L"\\Registry\\Machine"
#define DRIVER_REGKEY           L"%wS\\System\\CurrentControlSet\\Services\\%wS"

/*
* supHeapAlloc
*
* Purpose:
*
* Wrapper for RtlAllocateHeap.
*
*/
PVOID FORCEINLINE supHeapAlloc(
  _In_ SIZE_T Size
)
{
  return RtlAllocateHeap(NtCurrentPeb()->ProcessHeap, HEAP_ZERO_MEMORY, Size);
}

/*
* supHeapFree
*
* Purpose:
*
* Wrapper for RtlFreeHeap.
*
*/
BOOL FORCEINLINE supHeapFree(
  _In_ PVOID Memory
)
{
  return RtlFreeHeap(NtCurrentPeb()->ProcessHeap, 0, Memory);
}

/*
* supCallDriver
*
* Purpose:
*
* Call driver.
*
*/
NTSTATUS supCallDriver(
  _In_ HANDLE DeviceHandle,
  _In_ ULONG IoControlCode,
  _In_opt_ PVOID InputBuffer,
  _In_opt_ ULONG InputBufferLength,
  _In_opt_ PVOID OutputBuffer,
  _In_opt_ ULONG OutputBufferLength
)
{
  IO_STATUS_BLOCK IoStatus;

  return NtDeviceIoControlFile(
    DeviceHandle,
    nullptr,
    nullptr,
    nullptr,
    &IoStatus,
    IoControlCode,
    InputBuffer,
    InputBufferLength,
    OutputBuffer,
    OutputBufferLength
  );
}

/*
* supxDeleteKeyRecursive
*
* Purpose:
*
* Delete key and all it subkeys/values.
*
*/
BOOL supxDeleteKeyRecursive(
  _In_ HKEY KeyRoot,
  _In_ LPWSTR SubKey
)
{
  LPWSTR End;
  LONG Result;
  DWORD Size;
  WCHAR Name[MAX_PATH + 1];
  HKEY Key;
  FILETIME WriteTime;

  //
  // Attempt to delete key as is.
  //
  Result = RegDeleteKey(KeyRoot, SubKey);
  if (Result == ERROR_SUCCESS)
    return TRUE;

  //
  // Try to open key to check if it exist.
  //
  Result = RegOpenKeyEx(KeyRoot, SubKey, 0, KEY_READ, &Key);
  if (Result != ERROR_SUCCESS)
  {
    if (Result == ERROR_FILE_NOT_FOUND)
      return TRUE;
    else
      return FALSE;
  }

  //
  // Add slash to the key path if not present.
  //
  End = SubKey + wcslen(SubKey);
  if (*(End - 1) != TEXT('\\'))
  {
    *End = TEXT('\\');
    End++;
    *End = TEXT('\0');
  }

  //
  // Enumerate subkeys and call this func for each.
  //
  Size = MAX_PATH;
  Result = RegEnumKeyEx(
    Key,
    0,
    Name,
    &Size,
    nullptr,
    nullptr,
    nullptr,
    &WriteTime
  );

  if (Result == ERROR_SUCCESS)
  {
    do
    {
      wcsncpy(End, Name, MAX_PATH);

      if (!supxDeleteKeyRecursive(KeyRoot, SubKey))
        break;

      Size = MAX_PATH;

      Result = RegEnumKeyEx(
        Key,
        0,
        Name,
        &Size,
        nullptr,
        nullptr,
        nullptr,
        &WriteTime
      );
    }
    while (Result == ERROR_SUCCESS);
  }

  End--;
  *End = TEXT('\0');

  RegCloseKey(Key);

  //
  // Delete current key, all it subkeys should be already removed.
  //
  Result = RegDeleteKey(KeyRoot, SubKey);
  if (Result == ERROR_SUCCESS)
    return TRUE;

  return FALSE;
}

/*
* supRegDeleteKeyRecursive
*
* Purpose:
*
* Delete key and all it subkeys/values.
*
* Remark:
*
* SubKey should not be longer than 260 chars.
*
*/
BOOL supRegDeleteKeyRecursive(
  _In_ HKEY hKeyRoot,
  _In_ LPWSTR lpSubKey
)
{
  WCHAR KeyName[MAX_PATH + 1];
  RtlSecureZeroMemory(KeyName, sizeof(KeyName));
  wcsncpy(KeyName, lpSubKey, MAX_PATH);
  KeyName[MAX_PATH] = 0;
  return supxDeleteKeyRecursive(hKeyRoot, KeyName);
}

/*
* supEnablePrivilege
*
* Purpose:
*
* Enable/Disable given privilege.
*
* Return NTSTATUS value.
*
*/
NTSTATUS supEnablePrivilege(
  _In_ DWORD Privilege,
  _In_ BOOL Enable
)
{
  ULONG Length;
  NTSTATUS Status;
  HANDLE TokenHandle;
  LUID LuidPrivilege;

  PTOKEN_PRIVILEGES NewState;
  UCHAR Buffer[sizeof(TOKEN_PRIVILEGES) + sizeof(LUID_AND_ATTRIBUTES)];

  Status = NtOpenProcessToken(
    NtCurrentProcess(),
    TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY,
    &TokenHandle
  );

  if (!NT_SUCCESS(Status))
  {
    return Status;
  }

  NewState = (PTOKEN_PRIVILEGES)Buffer;

  LuidPrivilege = RtlConvertUlongToLuid(Privilege);

  NewState->PrivilegeCount = 1;
  NewState->Privileges[0].Luid = LuidPrivilege;
  NewState->Privileges[0].Attributes = Enable ? SE_PRIVILEGE_ENABLED : 0;

  Status = NtAdjustPrivilegesToken(
    TokenHandle,
    FALSE,
    NewState,
    sizeof(Buffer),
    nullptr,
    &Length
  );

  if (Status == STATUS_NOT_ALL_ASSIGNED)
  {
    Status = STATUS_PRIVILEGE_NOT_HELD;
  }

  NtClose(TokenHandle);
  return Status;
}

/*
* supxCreateDriverEntry
*
* Purpose:
*
* Creating registry entry for driver.
*
*/
NTSTATUS supxCreateDriverEntry(
  _In_opt_ LPCWSTR DriverPath,
  _In_ LPCWSTR KeyName
)
{
  NTSTATUS Status = STATUS_UNSUCCESSFUL;
  DWORD Data, Result;
  HKEY Handle = nullptr;
  UNICODE_STRING DriverImagePath;

  RtlInitEmptyUnicodeString(&DriverImagePath, NULL, 0);

  if (DriverPath)
  {
    if (!RtlDosPathNameToNtPathName_U(
      DriverPath,
      &DriverImagePath,
      nullptr,
      nullptr
    ))
    {
      return STATUS_INVALID_PARAMETER_2;
    }
  }

  if (ERROR_SUCCESS != RegCreateKeyEx(
    HKEY_LOCAL_MACHINE,
    KeyName,
    0,
    nullptr,
    REG_OPTION_NON_VOLATILE,
    KEY_ALL_ACCESS,
    nullptr,
    &Handle,
    nullptr
  ))
  {
    Status = STATUS_ACCESS_DENIED;
    goto Cleanup;
  }

  Result = ERROR_SUCCESS;

  do
  {
    Data = SERVICE_ERROR_NORMAL;
    Result = RegSetValueEx(
      Handle,
      TEXT("ErrorControl"),
      0,
      REG_DWORD,
      (BYTE*)&Data,
      sizeof(Data)
    );
    if (Result != ERROR_SUCCESS)
      break;

    Data = SERVICE_KERNEL_DRIVER;
    Result = RegSetValueEx(
      Handle,
      TEXT("Type"),
      0,
      REG_DWORD,
      (BYTE*)&Data,
      sizeof(Data)
    );
    if (Result != ERROR_SUCCESS)
      break;

    Data = SERVICE_DEMAND_START;
    Result = RegSetValueEx(
      Handle,
      TEXT("Start"),
      0,
      REG_DWORD,
      (BYTE*)&Data,
      sizeof(Data)
    );

    if (Result != ERROR_SUCCESS)
      break;

    if (DriverPath)
    {
      Result = RegSetValueEx(
        Handle,
        TEXT("ImagePath"),
        0,
        REG_EXPAND_SZ,
        (BYTE*)DriverImagePath.Buffer,
        (DWORD)DriverImagePath.Length + sizeof(UNICODE_NULL)
      );
    }
  }
  while (FALSE);

  RegCloseKey(Handle);

  if (Result != ERROR_SUCCESS)
  {
    Status = STATUS_ACCESS_DENIED;
  }
  else
  {
    Status = STATUS_SUCCESS;
  }

Cleanup:
  if (DriverPath)
  {
    if (DriverImagePath.Buffer)
    {
      RtlFreeUnicodeString(&DriverImagePath);
    }
  }
  return Status;
}

/*
* supLoadDriver
*
* Purpose:
*
* Install driver and load it.
*
* N.B.
* SE_LOAD_DRIVER_PRIVILEGE is required to be assigned and enabled.
*
*/
NTSTATUS supLoadDriver(
  _In_ LPCWSTR DriverName,
  _In_ LPCWSTR DriverPath,
  _In_ BOOLEAN UnloadPreviousInstance
)
{
  SIZE_T KeyOffset;
  NTSTATUS Status;
  UNICODE_STRING DriverServiceName;

  WCHAR Buffer[MAX_PATH + 1];

  if (DriverName == nullptr)
    return STATUS_INVALID_PARAMETER_1;
  if (DriverPath == nullptr)
    return STATUS_INVALID_PARAMETER_2;

  RtlSecureZeroMemory(Buffer, sizeof(Buffer));

  KeyOffset = RTL_NUMBER_OF(NT_REG_PREP);

  if (FAILED(
    StringCchPrintf(Buffer, MAX_PATH,
      DRIVER_REGKEY,
      NT_REG_PREP,
      DriverName)
  ))
  {
    return STATUS_INVALID_PARAMETER_1;
  }

  Status = supxCreateDriverEntry(
    DriverPath,
    &Buffer[KeyOffset]
  );

  if (!NT_SUCCESS(Status))
    return Status;

  RtlInitUnicodeString(&DriverServiceName, Buffer);
  Status = NtLoadDriver(&DriverServiceName);

  if (UnloadPreviousInstance)
  {
    if ((Status == STATUS_IMAGE_ALREADY_LOADED) ||
      (Status == STATUS_OBJECT_NAME_COLLISION) ||
      (Status == STATUS_OBJECT_NAME_EXISTS))
    {
      Status = NtUnloadDriver(&DriverServiceName);
      if (NT_SUCCESS(Status))
      {
        Status = NtLoadDriver(&DriverServiceName);
      }
    }
  }
  else
  {
    if (Status == STATUS_OBJECT_NAME_EXISTS)
      Status = STATUS_SUCCESS;
  }

  return Status;
}

/*
* supUnloadDriver
*
* Purpose:
*
* Call driver unload and remove corresponding registry key.
*
* N.B.
* SE_LOAD_DRIVER_PRIVILEGE is required to be assigned and enabled.
*
*/
NTSTATUS supUnloadDriver(
  _In_ LPCWSTR DriverName,
  _In_ BOOLEAN Remove
)
{
  NTSTATUS Status;
  SIZE_T KeyOffset;
  UNICODE_STRING DriverServiceName;

  WCHAR Buffer[MAX_PATH + 1];

  RtlSecureZeroMemory(Buffer, sizeof(Buffer));

  if (FAILED(
    StringCchPrintf(Buffer, MAX_PATH,
      DRIVER_REGKEY,
      NT_REG_PREP,
      DriverName)
  ))
  {
    return STATUS_INVALID_PARAMETER_1;
  }

  KeyOffset = RTL_NUMBER_OF(NT_REG_PREP);

  Status = supxCreateDriverEntry(
    nullptr,
    &Buffer[KeyOffset]
  );

  if (!NT_SUCCESS(Status))
    return Status;

  RtlInitUnicodeString(&DriverServiceName, Buffer);
  Status = NtUnloadDriver(&DriverServiceName);

  if (NT_SUCCESS(Status))
  {
    if (Remove)
      supRegDeleteKeyRecursive(HKEY_LOCAL_MACHINE, &Buffer[KeyOffset]);
  }

  return Status;
}

/*
* supOpenDriver
*
* Purpose:
*
* Open handle for helper driver.
*
*/
NTSTATUS supOpenDriver(
  _In_ LPCWSTR DriverName,
  _In_ ACCESS_MASK DesiredAccess,
  _Out_ PHANDLE DeviceHandle
)
{
  NTSTATUS Status = STATUS_UNSUCCESSFUL;

  UNICODE_STRING DeviceLink;
  OBJECT_ATTRIBUTES ObjectAttributes;
  IO_STATUS_BLOCK IoStatus;

  WCHAR DeviceLinkBuffer[MAX_PATH + 1];

  // assume failure
  if (DeviceHandle)
    *DeviceHandle = nullptr;
  else
    return STATUS_INVALID_PARAMETER_2;

  if (DriverName)
  {
    RtlSecureZeroMemory(DeviceLinkBuffer, sizeof(DeviceLinkBuffer));

    if (FAILED(
      StringCchPrintf(DeviceLinkBuffer,
        MAX_PATH,
        TEXT("\\DosDevices\\%wS"),
        DriverName)
    ))
    {
      return STATUS_INVALID_PARAMETER_1;
    }

    RtlInitUnicodeString(&DeviceLink, DeviceLinkBuffer);
    InitializeObjectAttributes(&ObjectAttributes, &DeviceLink, OBJ_CASE_INSENSITIVE, NULL, NULL);

    Status = NtCreateFile(
      DeviceHandle,
      DesiredAccess,
      &ObjectAttributes,
      &IoStatus,
      nullptr,
      0,
      0,
      FILE_OPEN,
      0,
      nullptr,
      0
    );
  }
  else
  {
    Status = STATUS_INVALID_PARAMETER_1;
  }

  return Status;
}

/*
* supQueryResourceData
*
* Purpose:
*
* Load resource by given id.
*
* N.B. Use supHeapFree to release memory allocated for the decompressed buffer.
*
*/
NTSTATUS supQueryResourceData(
  _In_ ULONG_PTR ResourceId,
  _In_ PVOID DllHandle,
  _Out_opt_ PVOID* Data,
  _Out_opt_ PULONG DataSize
)
{
  NTSTATUS Status = STATUS_UNSUCCESSFUL;
  ULONG_PTR IdPath[3];
  IMAGE_RESOURCE_DATA_ENTRY* DataEntry;
  PVOID PtrToData = nullptr;
  ULONG SizeOfData = 0;

  if (Data)
    *Data = nullptr;
  if (DataSize)
    *DataSize = 0;

  if (DllHandle != nullptr)
  {
    IdPath[0] = (ULONG_PTR)RT_RCDATA; //type
    IdPath[1] = ResourceId;           //id
    IdPath[2] = 0;                    //lang

    Status = LdrFindResource_U(DllHandle, IdPath, 3, &DataEntry);
    if (NT_SUCCESS(Status))
    {
      Status = LdrAccessResource(DllHandle, DataEntry, &PtrToData, &SizeOfData);
      if (NT_SUCCESS(Status))
      {
        if (Data)
          *Data = PtrToData;
        if (DataSize)
          *DataSize = SizeOfData;
      }
    }
  }
  return Status;
}

/*
* supWriteBufferToFile
*
* Purpose:
*
* Create new file (or open existing) and write (append) buffer to it.
*
*/
SIZE_T supWriteBufferToFile(
  _In_ PWSTR FileName,
  _In_ PVOID Buffer,
  _In_ SIZE_T Size,
  _In_ BOOL Flush,
  _Out_opt_ NTSTATUS* Result,
  _In_opt_ ULONG AdditionalAccessFlags,
  _Out_opt_ HANDLE* Handle
)
{
  NTSTATUS Status = STATUS_UNSUCCESSFUL;
  HANDLE File = nullptr;
  OBJECT_ATTRIBUTES ObjectAttributes;
  UNICODE_STRING NtFileName;
  IO_STATUS_BLOCK IoStatus;
  ULONG_PTR nBlocks, BlockIndex;
  ULONG BlockSize, RemainingSize;
  PUCHAR BytePtr = (PUCHAR)Buffer;
  SIZE_T BytesWritten = 0;

  if (Result)
    *Result = STATUS_UNSUCCESSFUL;
  if (Handle)
    *Handle = nullptr;

  if (RtlDosPathNameToNtPathName_U(FileName, &NtFileName, nullptr, nullptr) == FALSE)
  {
    if (Result)
      *Result = STATUS_INVALID_PARAMETER_1;
    return 0;
  }
  
  InitializeObjectAttributes(&ObjectAttributes, &NtFileName, OBJ_CASE_INSENSITIVE, nullptr, NULL);

  Status = NtCreateFile(
    &File,
    AdditionalAccessFlags | FILE_WRITE_ACCESS | SYNCHRONIZE,
    &ObjectAttributes,
    &IoStatus,
    nullptr,
    FILE_ATTRIBUTE_NORMAL,
    0,
    FILE_OVERWRITE_IF,
    FILE_SYNCHRONOUS_IO_NONALERT | FILE_NON_DIRECTORY_FILE,
    nullptr,
    0
  );

  if (!NT_SUCCESS(Status))
    goto fail;
  
  if (Size < 0x80000000)
  {
    BlockSize = (ULONG)Size;
    Status = NtWriteFile(File, nullptr, nullptr, nullptr, &IoStatus, BytePtr, BlockSize, nullptr, nullptr);
    if (!NT_SUCCESS(Status))
      goto fail;

    BytesWritten += IoStatus.Information;
  }
  else
  {
    BlockSize = 0x7FFFFFFF;
    nBlocks = (Size / BlockSize);
    for (BlockIndex = 0; BlockIndex < nBlocks; BlockIndex++)
    {
      Status = NtWriteFile(File, nullptr, nullptr, nullptr, &IoStatus, BytePtr, BlockSize, nullptr, nullptr);
      if (!NT_SUCCESS(Status))
        goto fail;

      BytePtr += BlockSize;
      BytesWritten += IoStatus.Information;
    }
    RemainingSize = (ULONG)(Size % BlockSize);
    if (RemainingSize != 0)
    {
      Status = NtWriteFile(File, nullptr, nullptr, nullptr, &IoStatus, BytePtr, RemainingSize, nullptr, nullptr);
      if (!NT_SUCCESS(Status))
        goto fail;
      BytesWritten += IoStatus.Information;
    }
  }

fail:
  if (File != nullptr)
  {
    if (Flush != FALSE)
      NtFlushBuffersFile(File, &IoStatus);
    if (NT_SUCCESS(Status) && Handle)
      *Handle = File;
    else
      NtClose(File);
  }
  RtlFreeUnicodeString(&NtFileName);
  if (Result)
    *Result = Status;

  return BytesWritten;
}

/*
* supMarkForDelete
*
* Purpose:
*
* Mark a file for deletion when all handles to it close.
*
*/
NTSTATUS supMarkForDelete(PWSTR FileName)
{
  NTSTATUS Status = STATUS_UNSUCCESSFUL;
  HANDLE File = nullptr;
  OBJECT_ATTRIBUTES ObjectAttributes;
  UNICODE_STRING NtFileName;
  IO_STATUS_BLOCK IoStatus;
  
  if (RtlDosPathNameToNtPathName_U(FileName, &NtFileName, nullptr, nullptr) == FALSE)
    return STATUS_INVALID_PARAMETER_1;

  InitializeObjectAttributes(&ObjectAttributes, &NtFileName, OBJ_CASE_INSENSITIVE, nullptr, NULL);

  Status = NtCreateFile(
    &File,
    DELETE | SYNCHRONIZE,
    &ObjectAttributes,
    &IoStatus,
    nullptr,
    FILE_ATTRIBUTE_NORMAL,
    FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
    FILE_OPEN,
    FILE_SYNCHRONOUS_IO_NONALERT | FILE_NON_DIRECTORY_FILE | FILE_DELETE_ON_CLOSE,
    nullptr,
    0
  );

  RtlFreeUnicodeString(&NtFileName);

  if (!NT_SUCCESS(Status))
    return Status;

  NtClose(File);

  return Status;
}

/*
* supExpandEnvironmentStrings
*
* Purpose:
*
* Reimplemented ExpandEnvironmentStrings.
*
*/
DWORD supExpandEnvironmentStrings(
  _In_ LPCWSTR Src,
  _Out_writes_to_opt_(Size, return) LPWSTR Dst,
  _In_ DWORD Size
)
{
  NTSTATUS Status;
  SIZE_T SrcLength = 0;
  SIZE_T ReturnLength = 0;
  SIZE_T DstLength = (SIZE_T)Size;

  if (Src)
  {
    SrcLength = wcslen(Src);
  }

  Status = RtlExpandEnvironmentStrings(
    nullptr,
    (PWSTR)Src,
    SrcLength,
    Dst,
    DstLength,
    &ReturnLength
  );

  if ((NT_SUCCESS(Status)) || (Status == STATUS_BUFFER_TOO_SMALL))
  {
    if (ReturnLength <= MAXDWORD32)
      return (DWORD)ReturnLength;

    Status = STATUS_UNSUCCESSFUL;
  }
  RtlSetLastWin32Error(RtlNtStatusToDosError(Status));
  return 0;
}


/*
* supReadFileToBuffer
*
* Purpose:
*
* Read file to buffer. Release memory when it no longer needed.
*
*/
PBYTE supReadFileToBuffer(
  _In_ LPWSTR FileName,
  _Inout_opt_ LPDWORD BufferSize
)
{
  NTSTATUS Status;
  HANDLE File = nullptr;
  PBYTE Buffer = nullptr;
  SIZE_T Size = 0;

  UNICODE_STRING Name;
  OBJECT_ATTRIBUTES ObjectAttributes;
  IO_STATUS_BLOCK IoStatus;
  FILE_STANDARD_INFORMATION Information;

  if (FileName == nullptr)
    return nullptr;

  Name.Buffer = nullptr;

  do
  {
    if (!RtlDosPathNameToNtPathName_U(FileName, &Name, nullptr, nullptr))
      break;

    InitializeObjectAttributes(&ObjectAttributes, &Name, OBJ_CASE_INSENSITIVE, NULL, NULL);

    Status = NtCreateFile(
      &File,
      FILE_READ_DATA | SYNCHRONIZE,
      &ObjectAttributes,
      &IoStatus,
      nullptr,
      FILE_ATTRIBUTE_NORMAL,
      FILE_SHARE_READ,
      FILE_OPEN,
      FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT,
      nullptr,
      0
    );

    if (!NT_SUCCESS(Status))
    {
      break;
    }

    RtlSecureZeroMemory(&Information, sizeof(Information));

    Status = NtQueryInformationFile(
      File,
      &IoStatus,
      &Information,
      sizeof(FILE_STANDARD_INFORMATION),
      FileStandardInformation
    );

    if (!NT_SUCCESS(Status))
      break;

    Size = (SIZE_T)Information.EndOfFile.LowPart;

    Buffer = (PBYTE)supHeapAlloc(Size);
    if (Buffer)
    {
      Status = NtReadFile(
        File,
        nullptr,
        nullptr,
        nullptr,
        &IoStatus,
        Buffer,
        Information.EndOfFile.LowPart,
        nullptr,
        nullptr
      );

      if (NT_SUCCESS(Status))
      {
        if (BufferSize)
          *BufferSize = Information.EndOfFile.LowPart;
      }
      else
      {
        supHeapFree(Buffer);
        Buffer = nullptr;
      }
    }
  }
  while (FALSE);

  if (File != nullptr)
  {
    NtClose(File);
  }

  if (Name.Buffer)
    RtlFreeUnicodeString(&Name);

  return Buffer;
}

/*
* supCreateSystemAdminAccessSD
*
* Purpose:
*
* Create security descriptor with Admin/System ACL set.
*
*/
NTSTATUS supCreateSystemAdminAccessSD(
  _Out_ PSECURITY_DESCRIPTOR* SecurityDescriptor,
  _Out_ PACL* DefaultAcl
)
{
  NTSTATUS Status = STATUS_UNSUCCESSFUL;
  ULONG AclSize = 0;
  SID_IDENTIFIER_AUTHORITY NtAuthority = SECURITY_NT_AUTHORITY;
  PACL Acl = nullptr;
  PSECURITY_DESCRIPTOR Descriptor = nullptr;

  UCHAR sidBuffer[2 * sizeof(SID)];

  *SecurityDescriptor = nullptr;
  *DefaultAcl = nullptr;

  do
  {
    RtlSecureZeroMemory(sidBuffer, sizeof(sidBuffer));

    Descriptor = supHeapAlloc(sizeof(SECURITY_DESCRIPTOR));
    if (Descriptor == nullptr)
    {
      Status = STATUS_INSUFFICIENT_RESOURCES;
      break;
    }

    AclSize += RtlLengthRequiredSid(1); //LocalSystem sid
    AclSize += RtlLengthRequiredSid(2); //Admin group sid
    AclSize += sizeof(ACL);
    AclSize += 2 * (sizeof(ACCESS_ALLOWED_ACE) - sizeof(ULONG));

    Acl = (PACL)supHeapAlloc(AclSize);
    if (Acl == nullptr)
    {
      Status = STATUS_INSUFFICIENT_RESOURCES;
      break;
    }

    Status = RtlCreateAcl(Acl, AclSize, ACL_REVISION);
    if (!NT_SUCCESS(Status))
      break;

    //
    // Local System - Generic All.
    //
    RtlInitializeSid(sidBuffer, &NtAuthority, 1);
    *(RtlSubAuthoritySid(sidBuffer, 0)) = SECURITY_LOCAL_SYSTEM_RID;
    RtlAddAccessAllowedAce(Acl, ACL_REVISION, GENERIC_ALL, sidBuffer);

    //
    // Admins - Generic All.
    //
    RtlInitializeSid(sidBuffer, &NtAuthority, 2);
    *(RtlSubAuthoritySid(sidBuffer, 0)) = SECURITY_BUILTIN_DOMAIN_RID;
    *(RtlSubAuthoritySid(sidBuffer, 1)) = DOMAIN_ALIAS_RID_ADMINS;
    RtlAddAccessAllowedAce(Acl, ACL_REVISION, GENERIC_ALL, sidBuffer);

    Status = RtlCreateSecurityDescriptor(
      Descriptor,
      SECURITY_DESCRIPTOR_REVISION1
    );
    if (!NT_SUCCESS(Status))
      break;

    Status = RtlSetDaclSecurityDescriptor(
      Descriptor,
      TRUE,
      Acl,
      FALSE
    );

    if (!NT_SUCCESS(Status))
      break;

    *SecurityDescriptor = Descriptor;
    *DefaultAcl = Acl;
  }
  while (FALSE);

  if (!NT_SUCCESS(Status))
  {
    if (Acl)
      supHeapFree(Acl);

    if (Descriptor)
    {
      supHeapFree(Descriptor);
    }

    *SecurityDescriptor = nullptr;
    *DefaultAcl = nullptr;
  }

  return Status;
}
