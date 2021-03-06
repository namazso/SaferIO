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
#define _NO_CRT_STDIO_INLINE
#define _CRT_SECURE_NO_WARNINGS
#include <ntstatus.h>
#define WIN32_NO_STATUS
#include <Windows.h>
#include <strsafe.h>
#include <intrin.h>
#include "ntos.h"

#include <cstdint>
#include <array>

#include "../SaferIO.h"
