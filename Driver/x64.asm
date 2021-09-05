;   SPDX-License-Identifier: LGPL-2.1-or-later
; 
;   We use LGPL 2.1 here since it lacks anti-tivoization clause which would
;   prevent Microsoft from WHQL signing it.
; 
;   SaferIO Driver - Simple giveio-style driver with secure access
;   Copyright (C) 2021  namazso <admin@namazso.eu>
; 
;   This library is free software; you can redistribute it and/or
;   modify it under the terms of the GNU Lesser General Public
;   License as published by the Free Software Foundation; either
;   version 2.1 of the License, or (at your option) any later version.
; 
;   This library is distributed in the hope that it will be useful,
;   but WITHOUT ANY WARRANTY; without even the implied warranty of
;   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
;   Lesser General Public License for more details.
; 
;   You should have received a copy of the GNU Lesser General Public
;   License along with this library; if not, write to the Free Software
;   Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA

.code

PUBLIC _dell

_dell PROC
	push rbx
	push rsi
	push rdi

	mov r8, rcx

	mov eax, [r8]
	mov ecx, [r8+4]
	mov edx, [r8+8]
	mov ebx, [r8+12]
	mov esi, [r8+16]
	mov edi, [r8+20]

	out 0b2h, al
	out 084h, al

	mov [r8], eax
	mov [r8+4], ecx
	mov [r8+8], edx
	mov [r8+12], ebx
	mov [r8+16], esi
	mov [r8+20], edi

	pop rdi
	pop rsi
	pop rbx

	xor eax, eax
	setb al

	ret
_dell ENDP

END