# Raw A.I.R.E. / PyGhidra evidence

Generated from analysis/index.json and analysis/xrefs.json. No symbols renamed.

Addresses are virtual addresses at preferred image base 00400000.

## String 'square of integer ' at 00419b38

```json
[
  {
    "from": "00412653",
    "to": "00419b38",
    "type": "DATA",
    "function": "00412620",
    "name": "FUN_00412620",
    "instruction": "PUSH 0x419b38"
  }
]
```

## String 'square of double ' at 00419b50

```json
[
  {
    "from": "004126fc",
    "to": "00419b50",
    "type": "DATA",
    "function": "004126c0",
    "name": "FUN_004126c0",
    "instruction": "PUSH 0x419b50"
  }
]
```

## String 'PAUSE' at 00419b68

```json
[
  {
    "from": "00412857",
    "to": "00419b68",
    "type": "DATA",
    "function": "00412790",
    "name": "FUN_00412790",
    "instruction": "PUSH 0x419b68"
  }
]
```

## thunk_FUN_00412620 @ 00411028

Signature: `int __cdecl thunk_FUN_00412620(int param_1)`

Assembly: 1 instructions; truncated: False.

Direct CALL callers:
- FUN_00412790 @ 00412790, callsite 004127ba

```c

/* WARNING: Function: __RTC_CheckEsp replaced with injection: __RTC_CheckEsp */

int __cdecl thunk_FUN_00412620(int param_1)

{
  basic_ostream<char,std::char_traits<char>_> *this;
  basic_ostream<char,struct_std::char_traits<char>_> *pbVar1;
  int iVar2;
  int unaff_EDI;
  undefined4 *puVar3;
  undefined4 auStack_c4 [48];
  
  puVar3 = auStack_c4;
  for (iVar2 = 0x30; iVar2 != 0; iVar2 = iVar2 + -1) {
    *puVar3 = 0xcccccccc;
    puVar3 = puVar3 + 1;
  }
  __CheckForDebuggerJustMyCode(&DAT_0041f027);
  this = (basic_ostream<char,std::char_traits<char>_> *)
         thunk_FUN_00411840((basic_ostream<char,std::char_traits<char>_> *)cout_exref,
                            "square of integer ");
  pbVar1 = std::basic_ostream<char,std::char_traits<char>_>::operator<<(this,unaff_EDI);
  thunk_FUN_00411840((basic_ostream<char,std::char_traits<char>_> *)pbVar1,(char *)0x412676);
  return param_1 * param_1;
}


```

```asm
00411028: JMP 0x00412620
```

## thunk_FUN_004126c0 @ 004110cd

Signature: `float10 __cdecl thunk_FUN_004126c0(undefined4 param_1, undefined4 param_2)`

Assembly: 1 instructions; truncated: False.

Direct CALL callers:
- FUN_00412790 @ 00412790, callsite 00412802

```c

/* WARNING: Function: __RTC_CheckEsp replaced with injection: __RTC_CheckEsp */

float10 __cdecl thunk_FUN_004126c0(undefined4 param_1,undefined4 param_2)

{
  basic_ostream<char,std::char_traits<char>_> *this;
  basic_ostream<char,struct_std::char_traits<char>_> *pbVar1;
  int iVar2;
  undefined4 unaff_EDI;
  undefined4 *puVar3;
  undefined *puVar4;
  undefined4 auStack_cc [50];
  
  puVar3 = auStack_cc;
  for (iVar2 = 0x32; iVar2 != 0; iVar2 = iVar2 + -1) {
    *puVar3 = 0xcccccccc;
    puVar3 = puVar3 + 1;
  }
  __CheckForDebuggerJustMyCode(&DAT_0041f027);
  puVar4 = &DAT_00419b30;
  this = (basic_ostream<char,std::char_traits<char>_> *)
         thunk_FUN_00411840((basic_ostream<char,std::char_traits<char>_> *)cout_exref,
                            "square of double ");
  pbVar1 = std::basic_ostream<char,std::char_traits<char>_>::operator<<
                     (this,(double)CONCAT44(unaff_EDI,puVar4));
  thunk_FUN_00411840((basic_ostream<char,std::char_traits<char>_> *)pbVar1,(char *)0x41271e);
  return (float10)((double)CONCAT44(param_2,param_1) * (double)CONCAT44(param_2,param_1));
}


```

```asm
004110cd: JMP 0x004126c0
```

## thunk_FUN_00412790 @ 00411325

Signature: `undefined4 __stdcall thunk_FUN_00412790(void)`

Assembly: 1 instructions; truncated: False.

Direct CALL callers:
- invoke_main @ 00413040, callsite 00413059

```c

/* WARNING: Function: __RTC_CheckEsp replaced with injection: __RTC_CheckEsp */

undefined4 thunk_FUN_00412790(void)

{
  basic_ostream<char,struct_std::char_traits<char>_> *this;
  int iVar1;
  undefined4 *puVar2;
  float10 fVar3;
  undefined4 auStack_c4 [48];
  
  puVar2 = auStack_c4;
  for (iVar1 = 0x30; iVar1 != 0; iVar1 = iVar1 + -1) {
    *puVar2 = 0xcccccccc;
    puVar2 = puVar2 + 1;
  }
  __CheckForDebuggerJustMyCode(&DAT_0041f027);
  iVar1 = thunk_FUN_00412620(7);
  std::basic_ostream<char,std::char_traits<char>_>::operator<<
            ((basic_ostream<char,std::char_traits<char>_> *)cout_exref,iVar1);
  std::basic_ostream<char,std::char_traits<char>_>::operator<<
            ((basic_ostream<char,std::char_traits<char>_> *)cout_exref,
             (_func_basic_ostream<char,struct_std::char_traits<char>_>_ptr_basic_ostream<char,struct_std::char_traits<char>_>_ptr
              *)&LAB_004112b7);
  fVar3 = thunk_FUN_004126c0((int)DAT_00419b70,(int)((ulonglong)DAT_00419b70 >> 0x20));
  std::basic_ostream<char,std::char_traits<char>_>::operator<<
            ((basic_ostream<char,std::char_traits<char>_> *)cout_exref,(double)fVar3);
  this = std::basic_ostream<char,std::char_traits<char>_>::operator<<
                   ((basic_ostream<char,std::char_traits<char>_> *)cout_exref,
                    (_func_basic_ostream<char,struct_std::char_traits<char>_>_ptr_basic_ostream<char,struct_std::char_traits<char>_>_ptr
                     *)&LAB_004112b7);
  std::basic_ostream<char,std::char_traits<char>_>::operator<<
            ((basic_ostream<char,std::char_traits<char>_> *)this,
             (_func_basic_ostream<char,struct_std::char_traits<char>_>_ptr_basic_ostream<char,struct_std::char_traits<char>_>_ptr
              *)0x412846);
  system("PAUSE");
  return 0;
}


```

```asm
00411325: JMP 0x00412790
```

## entry @ 004113ca

Signature: `undefined __stdcall entry(void)`

Assembly: 1 instructions; truncated: False.

Direct CALL callers:
- None (thunk JMPs are not CALL edges).

```c

void entry(void)

{
  __scrt_common_main();
  return;
}


```

```asm
004113ca: JMP 0x004130d0
```

## FUN_00412620 @ 00412620

Signature: `int __cdecl FUN_00412620(int param_1)`

Assembly: 39 instructions; truncated: False.

Direct CALL callers:
- None (thunk JMPs are not CALL edges).

```c

/* WARNING: Function: __RTC_CheckEsp replaced with injection: __RTC_CheckEsp */

int __cdecl FUN_00412620(int param_1)

{
  basic_ostream<char,std::char_traits<char>_> *this;
  basic_ostream<char,struct_std::char_traits<char>_> *pbVar1;
  int iVar2;
  int unaff_EDI;
  undefined4 *puVar3;
  undefined4 local_c4 [48];
  
  puVar3 = local_c4;
  for (iVar2 = 0x30; iVar2 != 0; iVar2 = iVar2 + -1) {
    *puVar3 = 0xcccccccc;
    puVar3 = puVar3 + 1;
  }
  __CheckForDebuggerJustMyCode(&DAT_0041f027);
  this = (basic_ostream<char,std::char_traits<char>_> *)
         thunk_FUN_00411840((basic_ostream<char,std::char_traits<char>_> *)cout_exref,
                            "square of integer ");
  pbVar1 = std::basic_ostream<char,std::char_traits<char>_>::operator<<(this,unaff_EDI);
  thunk_FUN_00411840((basic_ostream<char,std::char_traits<char>_> *)pbVar1,(char *)0x412676);
  return param_1 * param_1;
}


```

```asm
00412620: PUSH EBP
00412621: MOV EBP,ESP
00412623: SUB ESP,0xc0
00412629: PUSH EBX
0041262a: PUSH ESI
0041262b: PUSH EDI
0041262c: LEA EDI,[EBP + 0xffffff40]
00412632: MOV ECX,0x30
00412637: MOV EAX,0xcccccccc
0041263c: STOSD.REP ES:EDI
0041263e: MOV ECX,0x41f027
00412643: CALL 0x0041128a
00412648: PUSH 0x419b30
0041264d: MOV ESI,ESP
0041264f: MOV EAX,dword ptr [EBP + 0x8]
00412652: PUSH EAX
00412653: PUSH 0x419b38
00412658: MOV ECX,dword ptr [0x0041d0dc]
0041265e: PUSH ECX
0041265f: CALL 0x0041121c
00412664: ADD ESP,0x8
00412667: MOV ECX,EAX
00412669: CALL dword ptr [0x0041d0a4]
0041266f: CMP ESI,ESP
00412671: CALL 0x00411294
00412676: PUSH EAX
00412677: CALL 0x0041121c
0041267c: ADD ESP,0x8
0041267f: MOV EAX,dword ptr [EBP + 0x8]
00412682: IMUL EAX,dword ptr [EBP + 0x8]
00412686: POP EDI
00412687: POP ESI
00412688: POP EBX
00412689: ADD ESP,0xc0
0041268f: CMP EBP,ESP
00412691: CALL 0x00411294
00412696: MOV ESP,EBP
00412698: POP EBP
00412699: RET
```

## FUN_004126c0 @ 004126c0

Signature: `float10 __cdecl FUN_004126c0(undefined4 param_1, undefined4 param_2)`

Assembly: 42 instructions; truncated: False.

Direct CALL callers:
- None (thunk JMPs are not CALL edges).

```c

/* WARNING: Function: __RTC_CheckEsp replaced with injection: __RTC_CheckEsp */

float10 __cdecl FUN_004126c0(undefined4 param_1,undefined4 param_2)

{
  basic_ostream<char,std::char_traits<char>_> *this;
  basic_ostream<char,struct_std::char_traits<char>_> *pbVar1;
  int iVar2;
  undefined4 unaff_EDI;
  undefined4 *puVar3;
  undefined *puVar4;
  undefined4 local_cc [50];
  
  puVar3 = local_cc;
  for (iVar2 = 0x32; iVar2 != 0; iVar2 = iVar2 + -1) {
    *puVar3 = 0xcccccccc;
    puVar3 = puVar3 + 1;
  }
  __CheckForDebuggerJustMyCode(&DAT_0041f027);
  puVar4 = &DAT_00419b30;
  this = (basic_ostream<char,std::char_traits<char>_> *)
         thunk_FUN_00411840((basic_ostream<char,std::char_traits<char>_> *)cout_exref,
                            "square of double ");
  pbVar1 = std::basic_ostream<char,std::char_traits<char>_>::operator<<
                     (this,(double)CONCAT44(unaff_EDI,puVar4));
  thunk_FUN_00411840((basic_ostream<char,std::char_traits<char>_> *)pbVar1,(char *)0x41271e);
  return (float10)((double)CONCAT44(param_2,param_1) * (double)CONCAT44(param_2,param_1));
}


```

```asm
004126c0: PUSH EBP
004126c1: MOV EBP,ESP
004126c3: SUB ESP,0xc8
004126c9: PUSH EBX
004126ca: PUSH ESI
004126cb: PUSH EDI
004126cc: LEA EDI,[EBP + 0xffffff38]
004126d2: MOV ECX,0x32
004126d7: MOV EAX,0xcccccccc
004126dc: STOSD.REP ES:EDI
004126de: MOV ECX,0x41f027
004126e3: CALL 0x0041128a
004126e8: PUSH 0x419b30
004126ed: MOV ESI,ESP
004126ef: SUB ESP,0x8
004126f2: MOVSD XMM0,qword ptr [EBP + 0x8]
004126f7: MOVSD qword ptr [ESP],XMM0
004126fc: PUSH 0x419b50
00412701: MOV EAX,[0x0041d0dc]
00412706: PUSH EAX
00412707: CALL 0x0041121c
0041270c: ADD ESP,0x8
0041270f: MOV ECX,EAX
00412711: CALL dword ptr [0x0041d0a0]
00412717: CMP ESI,ESP
00412719: CALL 0x00411294
0041271e: PUSH EAX
0041271f: CALL 0x0041121c
00412724: ADD ESP,0x8
00412727: MOVSD XMM0,qword ptr [EBP + 0x8]
0041272c: MULSD XMM0,qword ptr [EBP + 0x8]
00412731: MOVSD qword ptr [EBP + 0xffffff38],XMM0
00412739: FLD double ptr [EBP + 0xffffff38]
0041273f: POP EDI
00412740: POP ESI
00412741: POP EBX
00412742: ADD ESP,0xc8
00412748: CMP EBP,ESP
0041274a: CALL 0x00411294
0041274f: MOV ESP,EBP
00412751: POP EBP
00412752: RET
```

## FUN_00412790 @ 00412790

Signature: `undefined4 __stdcall FUN_00412790(void)`

Assembly: 67 instructions; truncated: False.

Direct CALL callers:
- None (thunk JMPs are not CALL edges).

```c

/* WARNING: Function: __RTC_CheckEsp replaced with injection: __RTC_CheckEsp */

undefined4 FUN_00412790(void)

{
  basic_ostream<char,struct_std::char_traits<char>_> *this;
  int iVar1;
  undefined4 *puVar2;
  float10 fVar3;
  undefined4 local_c4 [48];
  
  puVar2 = local_c4;
  for (iVar1 = 0x30; iVar1 != 0; iVar1 = iVar1 + -1) {
    *puVar2 = 0xcccccccc;
    puVar2 = puVar2 + 1;
  }
  __CheckForDebuggerJustMyCode(&DAT_0041f027);
  iVar1 = thunk_FUN_00412620(7);
  std::basic_ostream<char,std::char_traits<char>_>::operator<<
            ((basic_ostream<char,std::char_traits<char>_> *)cout_exref,iVar1);
  std::basic_ostream<char,std::char_traits<char>_>::operator<<
            ((basic_ostream<char,std::char_traits<char>_> *)cout_exref,
             (_func_basic_ostream<char,struct_std::char_traits<char>_>_ptr_basic_ostream<char,struct_std::char_traits<char>_>_ptr
              *)&LAB_004112b7);
  fVar3 = thunk_FUN_004126c0((int)DAT_00419b70,(int)((ulonglong)DAT_00419b70 >> 0x20));
  std::basic_ostream<char,std::char_traits<char>_>::operator<<
            ((basic_ostream<char,std::char_traits<char>_> *)cout_exref,(double)fVar3);
  this = std::basic_ostream<char,std::char_traits<char>_>::operator<<
                   ((basic_ostream<char,std::char_traits<char>_> *)cout_exref,
                    (_func_basic_ostream<char,struct_std::char_traits<char>_>_ptr_basic_ostream<char,struct_std::char_traits<char>_>_ptr
                     *)&LAB_004112b7);
  std::basic_ostream<char,std::char_traits<char>_>::operator<<
            ((basic_ostream<char,std::char_traits<char>_> *)this,
             (_func_basic_ostream<char,struct_std::char_traits<char>_>_ptr_basic_ostream<char,struct_std::char_traits<char>_>_ptr
              *)0x412846);
  system("PAUSE");
  return 0;
}


```

```asm
00412790: PUSH EBP
00412791: MOV EBP,ESP
00412793: SUB ESP,0xc0
00412799: PUSH EBX
0041279a: PUSH ESI
0041279b: PUSH EDI
0041279c: LEA EDI,[EBP + 0xffffff40]
004127a2: MOV ECX,0x30
004127a7: MOV EAX,0xcccccccc
004127ac: STOSD.REP ES:EDI
004127ae: MOV ECX,0x41f027
004127b3: CALL 0x0041128a
004127b8: PUSH 0x7
004127ba: CALL 0x00411028
004127bf: ADD ESP,0x4
004127c2: MOV ESI,ESP
004127c4: PUSH EAX
004127c5: MOV ECX,dword ptr [0x0041d0dc]
004127cb: CALL dword ptr [0x0041d0a4]
004127d1: CMP ESI,ESP
004127d3: CALL 0x00411294
004127d8: MOV ESI,ESP
004127da: PUSH 0x4112b7
004127df: MOV ECX,dword ptr [0x0041d0dc]
004127e5: CALL dword ptr [0x0041d0a8]
004127eb: CMP ESI,ESP
004127ed: CALL 0x00411294
004127f2: SUB ESP,0x8
004127f5: MOVSD XMM0,qword ptr [0x00419b70]
004127fd: MOVSD qword ptr [ESP],XMM0
00412802: CALL 0x004110cd
00412807: ADD ESP,0x8
0041280a: MOV ESI,ESP
0041280c: SUB ESP,0x8
0041280f: FSTP double ptr [ESP]
00412812: MOV ECX,dword ptr [0x0041d0dc]
00412818: CALL dword ptr [0x0041d0a0]
0041281e: CMP ESI,ESP
00412820: CALL 0x00411294
00412825: MOV ESI,ESP
00412827: PUSH 0x4112b7
0041282c: MOV EDI,ESP
0041282e: PUSH 0x4112b7
00412833: MOV ECX,dword ptr [0x0041d0dc]
00412839: CALL dword ptr [0x0041d0a8]
0041283f: CMP EDI,ESP
00412841: CALL 0x00411294
00412846: MOV ECX,EAX
00412848: CALL dword ptr [0x0041d0a8]
0041284e: CMP ESI,ESP
00412850: CALL 0x00411294
00412855: MOV ESI,ESP
00412857: PUSH 0x419b68
0041285c: CALL dword ptr [0x0041d1d4]
00412862: ADD ESP,0x4
00412865: CMP ESI,ESP
00412867: CALL 0x00411294
0041286c: XOR EAX,EAX
0041286e: POP EDI
0041286f: POP ESI
00412870: POP EBX
00412871: ADD ESP,0xc0
00412877: CMP EBP,ESP
00412879: CALL 0x00411294
0041287e: MOV ESP,EBP
00412880: POP EBP
00412881: RET
```

## __scrt_common_main @ 00412d50

Signature: `int __cdecl __scrt_common_main(void)`

Assembly: 6 instructions; truncated: False.

Direct CALL callers:
- FUN_004130d0 @ 004130d0, callsite 004130d3

```c

/* Library Function - Single Match
    int __cdecl __scrt_common_main(void)
   
   Libraries: Visual Studio 2017 Debug, Visual Studio 2019 Debug */

int __cdecl __scrt_common_main(void)

{
  int iVar1;
  
  ___security_init_cookie();
  iVar1 = __scrt_common_main_seh();
  return iVar1;
}


```

```asm
00412d50: PUSH EBP
00412d51: MOV EBP,ESP
00412d53: CALL 0x0041133e
00412d58: CALL 0x00412d70
00412d5d: POP EBP
00412d5e: RET
```

## __scrt_common_main_seh @ 00412d70

Signature: `int __cdecl __scrt_common_main_seh(void)`

Assembly: 130 instructions; truncated: False.

Direct CALL callers:
- __scrt_common_main @ 00412d50, callsite 00412d58

```c

/* Library Function - Single Match
    int __cdecl __scrt_common_main_seh(void)
   
   Library: Visual Studio 2017 Debug */

int __cdecl __scrt_common_main_seh(void)

{
  code *pcVar1;
  bool bVar2;
  uint uVar3;
  undefined4 uVar4;
  int *piVar5;
  int iVar6;
  undefined4 uVar7;
  void *local_14;
  code *pcStack_10;
  uint local_c;
  undefined4 local_8;
  
  local_8 = 0xfffffffe;
  pcStack_10 = __except_handler4;
  local_14 = ExceptionList;
  local_c = DAT_0041c004 ^ 0x41b0a0;
  ExceptionList = &local_14;
  uVar7 = 1;
  uVar3 = ___scrt_initialize_crt(1);
  if ((uVar3 & 0xff) == 0) {
    uVar7 = 7;
    ___scrt_fastfail();
  }
  bVar2 = false;
  local_8 = 0;
  uVar4 = ___scrt_acquire_startup_lock();
  if (DAT_0041c520 == 1) {
    ___scrt_fastfail();
  }
  else if (DAT_0041c520 == 0) {
    DAT_0041c520 = 1;
    iVar6 = initterm_e(&DAT_0041930c,&DAT_00419618,uVar7);
    if (iVar6 != 0) {
      ExceptionList = local_14;
      return 0xff;
    }
    initterm(&DAT_00419000,&DAT_00419208);
    DAT_0041c520 = 2;
  }
  else {
    bVar2 = true;
  }
  ___scrt_release_startup_lock((char)uVar4);
  piVar5 = (int *)FID_conflict____scrt_get_dyn_tls_dtor_callback();
  if ((*piVar5 != 0) &&
     (uVar3 = ___scrt_is_nonwritable_in_current_image((int)piVar5), (uVar3 & 0xff) != 0)) {
    pcVar1 = (code *)*piVar5;
    (*(code *)PTR_guard_check_icall_00420000)(0,2,0);
    (*pcVar1)();
  }
  piVar5 = (int *)FID_conflict____scrt_get_dyn_tls_dtor_callback();
  if ((*piVar5 != 0) &&
     (uVar3 = ___scrt_is_nonwritable_in_current_image((int)piVar5), (uVar3 & 0xff) != 0)) {
    register_thread_local_exe_atexit_callback(*piVar5);
  }
  iVar6 = invoke_main();
  uVar3 = ___scrt_is_managed_app();
  if ((uVar3 & 0xff) != 0) {
    if (!bVar2) {
      _cexit();
    }
    ___scrt_uninitialize_crt(1,'\0');
    ExceptionList = local_14;
    return iVar6;
  }
                    /* WARNING: Subroutine does not return */
  exit(iVar6);
}


```

```asm
00412d70: PUSH EBP
00412d71: MOV EBP,ESP
00412d73: PUSH -0x2
00412d75: PUSH 0x41b0a0
00412d7a: PUSH 0x414d80
00412d7f: MOV EAX,FS:[0x0]
00412d85: PUSH EAX
00412d86: ADD ESP,-0x34
00412d89: PUSH EBX
00412d8a: PUSH ESI
00412d8b: PUSH EDI
00412d8c: MOV EAX,[0x0041c004]
00412d91: XOR dword ptr [EBP + -0x8],EAX
00412d94: XOR EAX,EBP
00412d96: PUSH EAX
00412d97: LEA EAX,[EBP + -0x10]
00412d9a: MOV FS:[0x0],EAX
00412da0: MOV dword ptr [EBP + -0x18],ESP
00412da3: PUSH 0x1
00412da5: CALL 0x0041116d
00412daa: ADD ESP,0x4
00412dad: MOVZX EAX,AL
00412db0: TEST EAX,EAX
00412db2: JNZ 0x00412dbb
00412db4: PUSH 0x7
00412db6: CALL 0x0041135c
00412dbb: MOV byte ptr [EBP + -0x19],0x0
00412dbf: MOV dword ptr [EBP + -0x4],0x0
00412dc6: CALL 0x00411410
00412dcb: MOV byte ptr [EBP + -0x1a],AL
00412dce: CMP dword ptr [0x0041c520],0x1
00412dd5: JNZ 0x00412de0
00412dd7: PUSH 0x7
00412dd9: CALL 0x0041135c
00412dde: JMP 0x00412e41
00412de0: CMP dword ptr [0x0041c520],0x0
00412de7: JNZ 0x00412e3d
00412de9: MOV dword ptr [0x0041c520],0x1
00412df3: PUSH 0x419618
00412df8: PUSH 0x41930c
00412dfd: CALL 0x0041108c
00412e02: ADD ESP,0x8
00412e05: TEST EAX,EAX
00412e07: JZ 0x00412e1f
00412e09: MOV dword ptr [EBP + -0x38],0xff
00412e10: MOV dword ptr [EBP + -0x4],0xfffffffe
00412e17: MOV EAX,dword ptr [EBP + -0x38]
00412e1a: JMP 0x00412f72
00412e1f: PUSH 0x419208
00412e24: PUSH 0x419000
00412e29: CALL 0x00411235
00412e2e: ADD ESP,0x8
00412e31: MOV dword ptr [0x0041c520],0x2
00412e3b: JMP 0x00412e41
00412e3d: MOV byte ptr [EBP + -0x19],0x1
00412e41: MOVZX ECX,byte ptr [EBP + -0x1a]
00412e45: PUSH ECX
00412e46: CALL 0x004110c3
00412e4b: ADD ESP,0x4
00412e4e: CALL 0x004111f4
00412e53: MOV dword ptr [EBP + -0x20],EAX
00412e56: MOV EDX,dword ptr [EBP + -0x20]
00412e59: CMP dword ptr [EDX],0x0
00412e5c: JZ 0x00412e91
00412e5e: MOV EAX,dword ptr [EBP + -0x20]
00412e61: PUSH EAX
00412e62: CALL 0x00411226
00412e67: ADD ESP,0x4
00412e6a: MOVZX ECX,AL
00412e6d: TEST ECX,ECX
00412e6f: JZ 0x00412e91
00412e71: MOV EDX,dword ptr [EBP + -0x20]
00412e74: MOV EAX,dword ptr [EDX]
00412e76: MOV dword ptr [EBP + -0x3c],EAX
00412e79: PUSH 0x0
00412e7b: PUSH 0x2
00412e7d: PUSH 0x0
00412e7f: MOV ECX,dword ptr [EBP + -0x3c]
00412e82: MOV dword ptr [EBP + -0x28],ECX
00412e85: MOV ECX,dword ptr [EBP + -0x28]
00412e88: CALL dword ptr [0x00420000]
00412e8e: CALL dword ptr [EBP + -0x28]
00412e91: CALL 0x004112b2
00412e96: MOV dword ptr [EBP + -0x24],EAX
00412e99: MOV EDX,dword ptr [EBP + -0x24]
00412e9c: CMP dword ptr [EDX],0x0
00412e9f: JZ 0x00412ec2
00412ea1: MOV EAX,dword ptr [EBP + -0x24]
00412ea4: PUSH EAX
00412ea5: CALL 0x00411226
00412eaa: ADD ESP,0x4
00412ead: MOVZX ECX,AL
00412eb0: TEST ECX,ECX
00412eb2: JZ 0x00412ec2
00412eb4: MOV EDX,dword ptr [EBP + -0x24]
00412eb7: MOV EAX,dword ptr [EDX]
00412eb9: PUSH EAX
00412eba: CALL 0x004110e1
00412ebf: ADD ESP,0x4
00412ec2: CALL 0x00413040
00412ec7: MOV dword ptr [EBP + -0x2c],EAX
00412eca: CALL 0x00411244
00412ecf: MOVZX ECX,AL
00412ed2: TEST ECX,ECX
00412ed4: JNZ 0x00412edf
00412ed6: MOV EDX,dword ptr [EBP + -0x2c]
00412ed9: PUSH EDX
00412eda: CALL 0x004112da
00412edf: MOVZX EAX,byte ptr [EBP + -0x19]
00412ee3: TEST EAX,EAX
00412ee5: JNZ 0x00412eec
00412ee7: CALL 0x0041101e
00412eec: PUSH 0x0
00412eee: PUSH 0x1
00412ef0: CALL 0x004112c6
00412ef5: ADD ESP,0x8
00412ef8: MOV ECX,dword ptr [EBP + -0x2c]
00412efb: MOV dword ptr [EBP + -0x40],ECX
00412efe: MOV dword ptr [EBP + -0x4],0xfffffffe
00412f05: MOV EAX,dword ptr [EBP + -0x40]
00412f08: JMP 0x00412f72
00412f72: MOV ECX,dword ptr [EBP + -0x10]
00412f75: MOV dword ptr FS:[0x0],ECX
00412f7c: POP ECX
00412f7d: POP EDI
00412f7e: POP ESI
00412f7f: POP EBX
00412f80: MOV ESP,EBP
00412f82: POP EBP
00412f83: RET
```

## invoke_main @ 00413040

Signature: `int __cdecl invoke_main(void)`

Assembly: 14 instructions; truncated: False.

Direct CALL callers:
- __scrt_common_main_seh @ 00412d70, callsite 00412ec2

```c

/* Library Function - Single Match
    int __cdecl invoke_main(void)
   
   Library: Visual Studio 2017 Debug */

int __cdecl invoke_main(void)

{
  undefined4 uVar1;
  undefined4 *puVar2;
  int iVar3;
  
  uVar1 = get_initial_narrow_environment();
  puVar2 = (undefined4 *)__p___argv(uVar1);
  __p___argc(*puVar2);
  iVar3 = thunk_FUN_00412790();
  return iVar3;
}


```

```asm
00413040: PUSH EBP
00413041: MOV EBP,ESP
00413043: CALL 0x004113ed
00413048: PUSH EAX
00413049: CALL 0x00411357
0041304e: MOV EAX,dword ptr [EAX]
00413050: PUSH EAX
00413051: CALL 0x004111ae
00413056: MOV ECX,dword ptr [EAX]
00413058: PUSH ECX
00413059: CALL 0x00411325
0041305e: ADD ESP,0xc
00413061: POP EBP
00413062: RET
```

## FUN_004130d0 @ 004130d0

Signature: `undefined __stdcall FUN_004130d0(void)`

Assembly: 5 instructions; truncated: False.

Direct CALL callers:
- None (thunk JMPs are not CALL edges).

```c

void FUN_004130d0(void)

{
  __scrt_common_main();
  return;
}


```

```asm
004130d0: PUSH EBP
004130d1: MOV EBP,ESP
004130d3: CALL 0x00412d50
004130d8: POP EBP
004130d9: RET
```
