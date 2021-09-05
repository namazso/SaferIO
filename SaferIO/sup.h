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
//  TITLE:       SUP.H
// 
//  VERSION:     1.11
// 
//  DATE:        14 May 2021
// 
//  Support routines header file.
#pragma once

PVOID FORCEINLINE supHeapAlloc(
  _In_ SIZE_T Size
);

BOOL FORCEINLINE supHeapFree(
  _In_ PVOID Memory
);

NTSTATUS supCallDriver(
  _In_ HANDLE DeviceHandle,
  _In_ ULONG IoControlCode,
  _In_opt_ PVOID InputBuffer,
  _In_opt_ ULONG InputBufferLength,
  _In_opt_ PVOID OutputBuffer,
  _In_opt_ ULONG OutputBufferLength
);

NTSTATUS supEnablePrivilege(
  _In_ DWORD Privilege,
  _In_ BOOL Enable
);

NTSTATUS supLoadDriver(
  _In_ LPCWSTR DriverName,
  _In_ LPCWSTR DriverPath,
  _In_ BOOLEAN UnloadPreviousInstance
);

NTSTATUS supUnloadDriver(
  _In_ LPCWSTR DriverName,
  _In_ BOOLEAN Remove
);

NTSTATUS supOpenDriver(
  _In_ LPCWSTR DriverName,
  _In_ ACCESS_MASK DesiredAccess,
  _Out_ PHANDLE DeviceHandle
);

NTSTATUS supQueryResourceData(
  _In_ ULONG_PTR ResourceId,
  _In_ PVOID DllHandle,
  _Out_opt_ PVOID* Data,
  _Out_opt_ PULONG DataSize
);

PBYTE supReadFileToBuffer(
  _In_ LPWSTR FileName,
  _Inout_opt_ LPDWORD BufferSize
);

SIZE_T supWriteBufferToFile(
  _In_ PWSTR FileName,
  _In_ PVOID Buffer,
  _In_ SIZE_T Size,
  _In_ BOOL Flush,
  _Out_opt_ NTSTATUS* Result,
  _In_opt_ ULONG AdditionalAccessFlags,
  _Out_opt_ HANDLE* Handle
);

NTSTATUS supMarkForDelete(
  _In_ PWSTR FileName
);

DWORD supExpandEnvironmentStrings(
  _In_ LPCWSTR Src,
  _Out_writes_to_opt_(Size, return) LPWSTR Dst,
  _In_ DWORD Size
);

NTSTATUS supCreateSystemAdminAccessSD(
  _Out_ PSECURITY_DESCRIPTOR* SecurityDescriptor,
  _Out_ PACL* DefaultAcl
);
