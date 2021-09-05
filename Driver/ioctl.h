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
#pragma once

#define SAFEIO_DEVICE_TYPE (0x8000)

enum IOCTL_CODES : ULONG
{
  // in:  USHORT  Port;
  // out: UCHAR   Value;
  // out: USHORT  Value;
  // out: ULONG   Value;
  IOCTL_IO_PORT_READ = (ULONG)CTL_CODE(SAFEIO_DEVICE_TYPE, 0x90C, METHOD_BUFFERED, FILE_READ_ACCESS),

  // in:  USHORT  Port; USHORT Reserved; UCHAR  Value;
  // in:  USHORT  Port; USHORT Reserved; USHORT Value;
  // in:  USHORT  Port; USHORT Reserved; ULONG  Value;
  // out: VOID;
  IOCTL_IO_PORT_WRITE = (ULONG)CTL_CODE(SAFEIO_DEVICE_TYPE, 0x90D, METHOD_BUFFERED, FILE_READ_ACCESS),

  // in:  ULONG   Index;
  // out: ULONG64 Value;
  IOCTL_MSR_READ = (ULONG)CTL_CODE(SAFEIO_DEVICE_TYPE, 0x912, METHOD_BUFFERED, FILE_READ_ACCESS),

  // in:  ULONG   Index; ULONG64  Value;
  // out: VOID;
  IOCTL_MSR_WRITE = (ULONG)CTL_CODE(SAFEIO_DEVICE_TYPE, 0x913, METHOD_BUFFERED, FILE_READ_ACCESS),

  // in:  ULONG64 PhysicalAddress;  ULONG Size;
  // out: PVOID   MappedAddress;
  IOCTL_PHYSMEM_MAP = (ULONG)CTL_CODE(SAFEIO_DEVICE_TYPE, 0x917, METHOD_BUFFERED, FILE_READ_ACCESS),

  // in:  PVOID   MappedAddress;
  // out: VOID;
  IOCTL_PHYSMEM_UNMAP = (ULONG)CTL_CODE(SAFEIO_DEVICE_TYPE, 0x918, METHOD_BUFFERED, FILE_READ_ACCESS),

  // in:  VOID;
  // out: ULONG RefCount;
  IOCTL_GET_REFCOUNT = (ULONG)CTL_CODE(SAFEIO_DEVICE_TYPE, 0x925, METHOD_BUFFERED, FILE_READ_ACCESS),

  // in:  ULONG64 PhysicalAddress;
  // out: UCHAR   Value;
  // out: USHORT  Value;
  // out: ULONG   Value;
  // out: ULONG64 Value;
  IOCTL_PHYSMEM_READ = (ULONG)CTL_CODE(SAFEIO_DEVICE_TYPE, 0x926, METHOD_BUFFERED, FILE_READ_ACCESS),

  // in:  ULONG64 PhysicalAddress;  UCHAR   Value;
  // in:  ULONG64 PhysicalAddress;  USHORT  Value;
  // in:  ULONG64 PhysicalAddress;  ULONG   Value;
  // in:  ULONG64 PhysicalAddress;  ULONG64 Value;
  // out: VOID;
  IOCTL_PHYSMEM_WRITE = (ULONG)CTL_CODE(SAFEIO_DEVICE_TYPE, 0x927, METHOD_BUFFERED, FILE_READ_ACCESS),

  // in:  IOCTL_PCI_CONFIG_CMD Cmd;
  // out: UCHAR[] but at most 255
  IOCTL_PCI_CONFIG_READ = (ULONG)CTL_CODE(SAFEIO_DEVICE_TYPE, 0x907, METHOD_BUFFERED, FILE_READ_ACCESS),

  // in:  IOCTL_PCI_CONFIG_CMD Cmd; UCHAR   Value;
  // in:  IOCTL_PCI_CONFIG_CMD Cmd; USHORT  Value;
  // in:  IOCTL_PCI_CONFIG_CMD Cmd; ULONG   Value;
  // out: VOID;
  IOCTL_PCI_CONFIG_WRITE = (ULONG)CTL_CODE(SAFEIO_DEVICE_TYPE, 0x908, METHOD_BUFFERED, FILE_READ_ACCESS),

  // in:  IOCTL_PCI_CONFIG_CMD Regs;
  // out: IOCTL_PCI_CONFIG_CMD Regs;
  IOCTL_DELL_SMM = (ULONG)CTL_CODE(SAFEIO_DEVICE_TYPE, 0x8FF, METHOD_BUFFERED, FILE_READ_ACCESS),
};

struct IOCTL_PCI_CONFIG_CMD
{
  UCHAR BusNumber;
  UCHAR DeviceNumber;
  UCHAR FunctionNumber;
  UCHAR Reserved;
  ULONG Offset;
};

struct IOCTL_DELL_SMM_REGS
{
  ULONG Eax;
  ULONG Ecx;
  ULONG Edx;
  ULONG Ebx;
  ULONG Esi;
  ULONG Edi;
};
