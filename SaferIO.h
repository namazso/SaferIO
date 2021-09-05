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
#pragma once

#define SAFERIO_CALLCONV __stdcall

#ifdef SAFERIO_EXPORTS
#define SAFERIO_DLLEXPORT __declspec(dllexport)
#else
#define SAFERIO_DLLEXPORT __declspec(dllimport)
#endif

#define SAFERIO_EXPORT(...) SAFERIO_DLLEXPORT __VA_ARGS__ SAFERIO_CALLCONV

#ifdef __cplusplus
#define SAFERIO_REF &
#else
#define SAFERIO_REF *
#endif

EXTERN_C_START

SAFERIO_EXPORT(NTSTATUS) DrvInitialize(PCWSTR Name);
SAFERIO_EXPORT(NTSTATUS) DrvUninitialize(PCWSTR Name);

SAFERIO_EXPORT(NTSTATUS) DrvGetRefCount(ULONG SAFERIO_REF RefCount);

SAFERIO_EXPORT(NTSTATUS) DrvIoPortReadByte(USHORT Port, UCHAR SAFERIO_REF Value);
SAFERIO_EXPORT(NTSTATUS) DrvIoPortReadWord(USHORT Port, USHORT SAFERIO_REF Value);
SAFERIO_EXPORT(NTSTATUS) DrvIoPortReadDword(USHORT Port, ULONG SAFERIO_REF Value);

SAFERIO_EXPORT(NTSTATUS) DrvIoPortWriteByte(USHORT Port, UCHAR Value);
SAFERIO_EXPORT(NTSTATUS) DrvIoPortWriteWord(USHORT Port, USHORT Value);
SAFERIO_EXPORT(NTSTATUS) DrvIoPortWriteDword(USHORT Port, ULONG Value);

SAFERIO_EXPORT(NTSTATUS) DrvMsrRead(ULONG Index, ULONG64 SAFERIO_REF Value);

SAFERIO_EXPORT(NTSTATUS) DrvMsrWrite(ULONG Index, ULONG64 Value);

SAFERIO_EXPORT(NTSTATUS) DrvPhysMap(ULONG64 Addr, ULONG Length, PVOID SAFERIO_REF MappedAddress);
SAFERIO_EXPORT(NTSTATUS) DrvPhysUnmap(PVOID MappedAddress);

SAFERIO_EXPORT(NTSTATUS) DrvPhysReadByte(ULONG64 Addr, UCHAR SAFERIO_REF Value);
SAFERIO_EXPORT(NTSTATUS) DrvPhysReadWord(ULONG64 Addr, USHORT SAFERIO_REF Value);
SAFERIO_EXPORT(NTSTATUS) DrvPhysReadDword(ULONG64 Addr, ULONG SAFERIO_REF Value);
SAFERIO_EXPORT(NTSTATUS) DrvPhysReadQword(ULONG64 Addr, ULONG64 SAFERIO_REF Value);

SAFERIO_EXPORT(NTSTATUS) DrvPhysWriteByte(ULONG64 Addr, UCHAR Value);
SAFERIO_EXPORT(NTSTATUS) DrvPhysWriteWord(ULONG64 Addr, USHORT Value);
SAFERIO_EXPORT(NTSTATUS) DrvPhysWriteDword(ULONG64 Addr, ULONG Value);
SAFERIO_EXPORT(NTSTATUS) DrvPhysWriteQword(ULONG64 Addr, ULONG64 Value);

SAFERIO_EXPORT(NTSTATUS) DrvPciConfigRead(UCHAR Bus, UCHAR Device, UCHAR Function, ULONG Offset, PVOID OutBuffer, UCHAR OutSize);

SAFERIO_EXPORT(NTSTATUS) DrvPciConfigWriteByte(UCHAR Bus, UCHAR Device, UCHAR Function, ULONG Offset, UCHAR Value);
SAFERIO_EXPORT(NTSTATUS) DrvPciConfigWriteWord(UCHAR Bus, UCHAR Device, UCHAR Function, ULONG Offset, USHORT Value);
SAFERIO_EXPORT(NTSTATUS) DrvPciConfigWriteDword(UCHAR Bus, UCHAR Device, UCHAR Function, ULONG Offset, ULONG Value);

EXTERN_C_END
