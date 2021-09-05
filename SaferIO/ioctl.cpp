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
#include "ioctl.h"

template <typename T>
__forceinline std::array<uint8_t, sizeof(T)> AsBytes(const T& Value)
{
  const auto Address = (const uint8_t*)std::addressof(Value);
  std::array<uint8_t, sizeof(T)> Array{};
  std::copy(Address, Address + sizeof(T), Array.begin());
  return Array;
}

template<std::size_t... Args>
__forceinline constexpr auto Sum() -> std::size_t
{
  return (Args + ... + 0);
}

template <typename T, std::size_t... Size>
__forceinline constexpr auto FlattenArray(std::array<T, Size>... Arrays)
{
  constexpr std::size_t NbArray = sizeof...(Arrays);

  T* Data[NbArray] = { &Arrays[0]... };
  constexpr std::size_t Lengths[NbArray] = { Arrays.size()... };

  constexpr std::size_t FlatLength = Sum<Arrays.size()...>();

  std::array<T, FlatLength> FlatArray = { 0 };

  size_t Index = 0;
  for (size_t i = 0; i < NbArray; i++)
  {
    for (size_t j = 0; j < Lengths[i]; j++)
    {
      FlatArray[Index] = Data[i][j];
      Index++;
    }
  }

  return FlatArray;
}

constexpr std::array<std::uint8_t, 0> FlattenArray() { return {}; }

template <typename... Args>
__forceinline auto MakeArray(const Args&... Args_)
{
  return FlattenArray(AsBytes(Args_)...);
}

NTSTATUS IoCtl(ULONG Code, PVOID InputBuffer, ULONG InputBufferLength, PVOID OutputBuffer, ULONG OutputBufferLength);

template <typename Out, typename... In>
BOOL DoIoCtl(ULONG Code, Out&& OutVar, const In&... InVars)
{
  auto InPacked = MakeArray(InVars...);
  constexpr auto OutSize = std::is_same_v<std::decay_t<Out>, std::monostate> ? 0 : sizeof(OutVar);
  return IoCtl(
    Code,
    (PVOID)InPacked.data(),
    (ULONG)InPacked.size(),
    (PVOID)&OutVar,
    (ULONG)OutSize
  );
}

SAFERIO_EXPORT(NTSTATUS) DrvGetRefCount(ULONG& RefCount) { return DoIoCtl(IOCTL_GET_REFCOUNT, RefCount); }

SAFERIO_EXPORT(NTSTATUS) DrvIoPortReadByte(USHORT Port, UCHAR& Value) { return DoIoCtl(IOCTL_IO_PORT_READ, Value, Port); }
SAFERIO_EXPORT(NTSTATUS) DrvIoPortReadWord(USHORT Port, USHORT& Value) { return DoIoCtl(IOCTL_IO_PORT_READ, Value, Port); }
SAFERIO_EXPORT(NTSTATUS) DrvIoPortReadDword(USHORT Port, ULONG& Value) { return DoIoCtl(IOCTL_IO_PORT_READ, Value, Port); }

SAFERIO_EXPORT(NTSTATUS) DrvIoPortWriteByte(USHORT Port, UCHAR Value) { return DoIoCtl(IOCTL_IO_PORT_WRITE, std::monostate{}, Port, (USHORT)0, Value); }
SAFERIO_EXPORT(NTSTATUS) DrvIoPortWriteWord(USHORT Port, USHORT Value) { return DoIoCtl(IOCTL_IO_PORT_WRITE, std::monostate{}, Port, (USHORT)0, Value); }
SAFERIO_EXPORT(NTSTATUS) DrvIoPortWriteDword(USHORT Port, ULONG Value) { return DoIoCtl(IOCTL_IO_PORT_WRITE, std::monostate{}, Port, (USHORT)0, Value); }

SAFERIO_EXPORT(NTSTATUS) DrvMsrRead(ULONG Index, ULONG64& Value) { return DoIoCtl(IOCTL_MSR_READ, Value, Index); }

SAFERIO_EXPORT(NTSTATUS) DrvMsrWrite(ULONG Index, ULONG64 Value) { return DoIoCtl(IOCTL_MSR_WRITE, std::monostate{}, Index, Value); }

SAFERIO_EXPORT(NTSTATUS) DrvPhysReadByte(ULONG64 Addr, UCHAR& Value) { return DoIoCtl(IOCTL_PHYSMEM_READ, Value, Addr); }
SAFERIO_EXPORT(NTSTATUS) DrvPhysReadWord(ULONG64 Addr, USHORT& Value) { return DoIoCtl(IOCTL_PHYSMEM_READ, Value, Addr); }
SAFERIO_EXPORT(NTSTATUS) DrvPhysReadDword(ULONG64 Addr, ULONG& Value) { return DoIoCtl(IOCTL_PHYSMEM_READ, Value, Addr); }
SAFERIO_EXPORT(NTSTATUS) DrvPhysReadQword(ULONG64 Addr, ULONG64& Value) { return DoIoCtl(IOCTL_PHYSMEM_READ, Value, Addr); }

SAFERIO_EXPORT(NTSTATUS) DrvPhysWriteByte(ULONG64 Addr, UCHAR Value) { return DoIoCtl(IOCTL_PHYSMEM_WRITE, std::monostate{}, Addr, Value); }
SAFERIO_EXPORT(NTSTATUS) DrvPhysWriteWord(ULONG64 Addr, USHORT Value) { return DoIoCtl(IOCTL_PHYSMEM_WRITE, std::monostate{}, Addr, Value); }
SAFERIO_EXPORT(NTSTATUS) DrvPhysWriteDword(ULONG64 Addr, ULONG Value) { return DoIoCtl(IOCTL_PHYSMEM_WRITE, std::monostate{}, Addr, Value); }
SAFERIO_EXPORT(NTSTATUS) DrvPhysWriteQword(ULONG64 Addr, ULONG64 Value) { return DoIoCtl(IOCTL_PHYSMEM_WRITE, std::monostate{}, Addr, Value); }

SAFERIO_EXPORT(NTSTATUS) DrvPciConfigRead(UCHAR Bus, UCHAR Device, UCHAR Function, ULONG Offset, PVOID OutBuffer, UCHAR OutSize)
{
  IOCTL_PCI_CONFIG_CMD Cmd{};
  Cmd.BusNumber = Bus;
  Cmd.DeviceNumber = Device;
  Cmd.FunctionNumber = Function;
  Cmd.Offset = Offset;
  return IoCtl(
    IOCTL_PCI_CONFIG_READ,
    &Cmd,
    (ULONG)sizeof(Cmd),
    OutBuffer,
    (ULONG)OutSize
  );
}

SAFERIO_EXPORT(NTSTATUS) DrvPciConfigWriteByte(UCHAR Bus, UCHAR Device, UCHAR Function, ULONG Offset, UCHAR Value)
{
  IOCTL_PCI_CONFIG_CMD Cmd{};
  Cmd.BusNumber = Bus;
  Cmd.DeviceNumber = Device;
  Cmd.FunctionNumber = Function;
  Cmd.Offset = Offset;
  return DoIoCtl(IOCTL_PCI_CONFIG_WRITE, std::monostate{}, Cmd, Value);
}

SAFERIO_EXPORT(NTSTATUS) DrvPciConfigWriteWord(UCHAR Bus, UCHAR Device, UCHAR Function, ULONG Offset, USHORT Value)
{
  IOCTL_PCI_CONFIG_CMD Cmd{};
  Cmd.BusNumber = Bus;
  Cmd.DeviceNumber = Device;
  Cmd.FunctionNumber = Function;
  Cmd.Offset = Offset;
  return DoIoCtl(IOCTL_PCI_CONFIG_WRITE, std::monostate{}, Cmd, Value);
}

SAFERIO_EXPORT(NTSTATUS) DrvPciConfigWriteDword(UCHAR Bus, UCHAR Device, UCHAR Function, ULONG Offset, ULONG Value)
{
  IOCTL_PCI_CONFIG_CMD Cmd{};
  Cmd.BusNumber = Bus;
  Cmd.DeviceNumber = Device;
  Cmd.FunctionNumber = Function;
  Cmd.Offset = Offset;
  return DoIoCtl(IOCTL_PCI_CONFIG_WRITE, std::monostate{}, Cmd, Value);
}

SAFERIO_EXPORT(NTSTATUS) DrvPhysMap(ULONG64 Addr, ULONG Length, PVOID& MappedAddress)
{
  return DoIoCtl(IOCTL_PHYSMEM_MAP, MappedAddress, Addr, Length);
}

SAFERIO_EXPORT(NTSTATUS) DrvPhysUnmap(PVOID MappedAddress)
{
  return DoIoCtl(IOCTL_PHYSMEM_UNMAP, std::monostate{}, MappedAddress);
}
