// public domain
#include <Windows.h>
#include <cstdio>
#include "../SaferIO.h"

constexpr static auto APP_NAME = L"TestApp";

int main()
{
  enum : ULONG { IA32_KERNEL_GS_BASE = 0xC0000102 };

  NTSTATUS Status = DrvInitialize(APP_NAME);
  printf("DrvInitialize returned: %08X\n", Status);
  ULONG64 GsBase{};
  ULONG64 Teb = (ULONG64)NtCurrentTeb();
  Status = DrvMsrRead(IA32_KERNEL_GS_BASE, GsBase);
  printf("DrvMsrRead returned: %08X, GsBase = %016llX, TEB = %016llX\n", Status, GsBase, Teb);
  Status = DrvUninitialize(APP_NAME);
  printf("DrvUninitialize returned: %08X\n", Status);
  return 0;
}
