///usr/bin/env x86_64-elf-gcc -fdebug-prefix-map=$(pwd)=. -g -Wa,-msyntax=intel,-mnaked-reg -nostdlib -o "${0%.S}.elf" "$0"; exit

/*
 * GDB:
 *     dprintf _00000000,"%08x eax=%08x ebx=%08x ecx=%08x edx=%08x\n",$esi,$eax,$ebx,$ecx,$edx
 *     dprintf _40000000,"%08x eax=%08x ebx=%08x ecx=%08x edx=%08x\n",$esi,$eax,$ebx,$ecx,$edx
 *     dprintf _80000000,"%08x eax=%08x ebx=%08x ecx=%08x edx=%08x\n",$esi,$eax,$ebx,$ecx,$edx
 */

.global _start
_start:

    mov eax,0
    cpuid
    mov esi,0
    mov edi,eax
loop_00000000:
    mov eax,esi
    cpuid
_00000000:
    nop
    inc esi
    cmp esi,edi
    jbe loop_00000000

    mov eax,0x40000000
    cpuid
    mov esi,0x40000000
    mov edi,eax
loop_40000000:
    mov eax,esi
    cpuid
_40000000:
    nop
    inc esi
    cmp esi,edi
    jbe loop_40000000

    mov eax,0x80000000
    cpuid
    mov esi,0x80000000
    mov edi,eax
loop_80000000:
    mov eax,esi
    cpuid
_80000000:
    nop
    inc esi
    cmp esi,edi
    jbe loop_80000000

    hlt
