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

.386
.model flat
.code

PUBLIC @_dell@4

@_dell@4 PROC
	push ebx
	push esi
	push edi
	push ebp

	mov ebp, ecx

	mov eax, [ebp]
	mov ecx, [ebp+4]
	mov edx, [ebp+8]
	mov ebx, [ebp+12]
	mov esi, [ebp+16]
	mov edi, [ebp+20]

	out 0b2h, al
	out 084h, al

	mov [ebp], eax
	mov [ebp+4], ecx
	mov [ebp+8], edx
	mov [ebp+12], ebx
	mov [ebp+16], esi
	mov [ebp+20], edi

	pop ebp
	pop edi
	pop esi
	pop ebx

	setb al
	movzx eax, al

	ret
@_dell@4 ENDP

END