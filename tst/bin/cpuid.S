///usr/bin/env x86_64-elf-gcc -fdebug-prefix-map=$(pwd)=. -g -Wa,-msyntax=intel,-mnaked-reg -nostdlib -o "${0%.S}.elf" "$0"; exit

/*
 * GDB:
 *     dprintf dp_cpuid,"0x%08x 0x%02x: eax=0x%08x ebx=0x%08x ecx=0x%08x edx=0x%08x\n",$esi,$edi,$eax,$ebx,$ecx,$edx
 */

.global _start
_start:

    lea rsp,[rip+0x1000]

    mov eax,0                           // request basic CPUID information
    call do_leafs

    mov eax,0x40000000                  // request hypervisor CPUID information
    call do_leafs

    mov eax,0x80000000                  // request extended CPUID information
    call do_leafs

    hlt

do_leafs:
    mov esi,eax
    cpuid
    mov ebp,eax                         // maximum input for CPUID information
.Lloop:
    cmp esi,0x20
    ja .Lnosubleafs
    mov rax,[esi*8+subleafs]
    test rax,rax
    jz .Lnosubleafs
    call rax
    jmp .Lloopcont
.Lnosubleafs:
    mov eax,esi
    xor edi,edi
    xor ecx,ecx
    cpuid
    call dp_cpuid
.Lloopcont:
    inc esi
    cmp esi,ebp
    jbe .Lloop
    ret

do_leaf04_subleafs:
    xor edi,edi
.Ll04loop:
    mov eax,esi
    mov ecx,edi
    cpuid
    call dp_cpuid
    inc edi
    test eax,0x1f
    jnz .Ll04loop
    ret

do_leaf07_subleafs:
    mov r8,rbp
    mov eax,esi
    mov ecx,0
    cpuid
    mov ebp,eax                         // maximum subleaf
    xor edi,edi
.Ll07loop:
    mov eax,esi
    mov ecx,edi
    cpuid
    call dp_cpuid
    inc edi
    cmp edi,ebp
    jbe .Ll07loop
    mov rbp,r8
    ret

do_leaf0b_subleafs:
    xor edi,edi
.Ll0bloop:
    mov eax,esi
    mov ecx,edi
    cpuid
    call dp_cpuid
    inc edi
    test ecx,0xff00
    jnz .Ll0bloop
    ret

do_leaf0d_subleafs:
    mov r8,rbp
    mov ebp,63
    xor edi,edi
.Ll0dloop:
    mov eax,esi
    mov ecx,edi
    cpuid
    mov r9,rax
    or r9,rbx
    or r9,rcx
    or r9,rdx
    jz .Ll0dskip
    call dp_cpuid
.Ll0dskip:
    inc edi
    cmp edi,ebp
    jbe .Ll0dloop
    mov rbp,r8
    ret

do_leaf0f_subleafs:
    mov eax,esi
    mov ecx,0
    cpuid
    call dp_cpuid
    mov eax,esi
    mov ecx,1
    cpuid
    call dp_cpuid
    ret

// TODO
do_leaf10_subleafs:
    mov eax,esi
    xor edi,edi
    xor ecx,ecx
    cpuid
    call dp_cpuid
    ret

// TODO
do_leaf12_subleafs:
    mov eax,esi
    xor edi,edi
    xor ecx,ecx
    cpuid
    call dp_cpuid
    ret

// TODO
do_leaf14_subleafs:
    mov eax,esi
    xor edi,edi
    xor ecx,ecx
    cpuid
    call dp_cpuid
    ret

// TODO
do_leaf17_subleafs:
    mov eax,esi
    xor edi,edi
    xor ecx,ecx
    cpuid
    call dp_cpuid
    ret

// TODO
do_leaf18_subleafs:
    mov eax,esi
    xor edi,edi
    xor ecx,ecx
    cpuid
    call dp_cpuid
    ret

// TODO
do_leaf1a_subleafs:
    mov eax,esi
    xor edi,edi
    xor ecx,ecx
    cpuid
    call dp_cpuid
    ret

// TODO
do_leaf1b_subleafs:
    mov eax,esi
    xor edi,edi
    xor ecx,ecx
    cpuid
    call dp_cpuid
    ret

// TODO
do_leaf1d_subleafs:
    mov eax,esi
    xor edi,edi
    xor ecx,ecx
    cpuid
    call dp_cpuid
    ret

// TODO
do_leaf1e_subleafs:
    mov eax,esi
    xor edi,edi
    xor ecx,ecx
    cpuid
    call dp_cpuid
    ret

// TODO
do_leaf20_subleafs:
    mov eax,esi
    xor edi,edi
    xor ecx,ecx
    cpuid
    call dp_cpuid
    ret

subleafs:
    .quad 0                             # 00
    .quad 0                             # 01
    .quad 0                             # 02
    .quad 0                             # 03
    .quad do_leaf04_subleafs            # 04
    .quad 0                             # 05
    .quad 0                             # 06
    .quad do_leaf07_subleafs            # 07
    .quad 0                             # 08
    .quad 0                             # 09
    .quad 0                             # 0a
    .quad do_leaf0b_subleafs            # 0b
    .quad 0                             # 0c
    .quad do_leaf0d_subleafs            # 0d
    .quad 0                             # 0e
    .quad do_leaf0f_subleafs            # 0f
    .quad do_leaf10_subleafs            # 10
    .quad 0                             # 11
    .quad do_leaf12_subleafs            # 12
    .quad 0                             # 13
    .quad do_leaf14_subleafs            # 14
    .quad 0                             # 15
    .quad 0                             # 16
    .quad do_leaf17_subleafs            # 17
    .quad do_leaf18_subleafs            # 18
    .quad 0                             # 19
    .quad do_leaf1a_subleafs            # 1a
    .quad do_leaf1b_subleafs            # 1b
    .quad 0                             # 1c
    .quad do_leaf1d_subleafs            # 1d
    .quad do_leaf1e_subleafs            # 1e
    .quad 0                             # 1f
    .quad do_leaf20_subleafs            # 20

dp_cpuid:
    ret
