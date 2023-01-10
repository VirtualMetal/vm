///usr/bin/env x86_64-elf-gcc -fdebug-prefix-map=$(pwd)=. -g -Wa,-msyntax=intel,-mnaked-reg -nostdlib -o "${0%.S}.elf" "$0"; exit

/*
 * GDB:
 *     dprintf _00000000,"%08x eax=%08x ebx=%08x ecx=%08x edx=%08x\n",$esi,$eax,$ebx,$ecx,$edx
 *     dprintf _40000000,"%08x eax=%08x ebx=%08x ecx=%08x edx=%08x\n",$esi,$eax,$ebx,$ecx,$edx
 *     dprintf _80000000,"%08x eax=%08x ebx=%08x ecx=%08x edx=%08x\n",$esi,$eax,$ebx,$ecx,$edx
 */

.global _start
_start:

    mov eax,0                           // request basic CPUID information
    mov esi,eax
    cpuid
    mov edi,eax                         // maximum input for basic CPUID information
loop_00000000:
    mov eax,esi
    xor ecx,ecx
    cpuid
_00000000:
    nop                                 // dprintf _00000000
    inc esi
    cmp esi,edi
    jbe loop_00000000

    mov eax,0x40000000                  // request hypervisor CPUID information
    mov esi,eax
    cpuid
    mov edi,eax                         // maximum input for hypervisor CPUID information
loop_40000000:
    mov eax,esi
    xor ecx,ecx
    cpuid
_40000000:
    nop                                 // dprintf _40000000
    inc esi
    cmp esi,edi
    jbe loop_40000000

    mov eax,0x80000000                  // request extended CPUID information
    mov esi,eax
    cpuid
    mov edi,eax                         // maximum input for extended CPUID information
loop_80000000:
    mov eax,esi
    xor ecx,ecx
    cpuid
_80000000:
    nop                                 // dprintf _80000000
    inc esi
    cmp esi,edi
    jbe loop_80000000

    hlt
