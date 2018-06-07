```asm
.text:00051108 FF 15 BC 90 AB 00       call    ds:GetModuleHandleExW
.text:0005110E 48                      dec     eax
.text:0005110F F7 D8                   neg     eax
.text:00051111 1B C0                   sbb     eax, eax
.text:00051113 40                      inc     eax
.text:00051114 59                      pop     ecx
.text:00051115 C3                      retn
.text:00051115                         sub_A410B0 endp
.text:00A41115
```
```asm
.text:00A27995 8B 44 81 40             mov     eax, [ecx+eax*4+40h]
.text:00A27999 C3                      retn
```
```asm
.text:009F5E29 8B C1                   mov     eax, ecx
.text:009F5E2B 5D                      pop     ebp
.text:009F5E2C C3                      retn
```
```asm
.text:00A1A1E0 8B 44 24 04             mov     eax, [esp+arg_0] ; +4
.text:00A1A1E4 85 C0                   test    eax, eax
.text:00A1A1E6 75 04                   jnz     short loc_A1A1EC
.text:00A1A1EC 8B 00                   mov     eax, [eax]
.text:00A1A1EE C3                      retn
```
```asm
.text:00A268CA 8B D0                   mov     edx, eax
.text:00A268CC 33 C0                   xor     eax, eax
.text:00A268CE 83 FA FF                cmp     edx, 0FFFFFFFFh
.text:00A268D1 0F 95 C0                setnz   al
.text:00A268D4 89 11                   mov     [ecx], edx
.text:00A268D6 C3                      retn
```
```asm
.text:00A3CA6D 89 54 24 04             mov     [esp+arg_0], edx
.text:00A3CA71 FF E0                   jmp     eax
```
```asm
.text:009F1A61 59                      pop     ecx
.text:009F1A62 C3                      retn
```
```asm
.text:00A001E4 FF D0                   call    eax ; sub_A05880
.text:00A001E6 83 C4 04                add     esp, 4
.text:00A001E9 5F                      pop     edi
.text:00A001EA 5E                      pop     esi
.text:00A001EB 5B                      pop     ebx
.text:00A001EC 5D                      pop     ebp
.text:00A001ED C3                      retn
```