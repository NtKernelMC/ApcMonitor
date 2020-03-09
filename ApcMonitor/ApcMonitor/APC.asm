IFNDEF AMD64
	.686P
    .XMM
    .MODEL FLAT, STDCALL
    EXTERN ApcHandler@12: NEAR
ELSE
    EXTERN ApcHandler: NEAR
ENDIF

EXTERN OriginalApcDispatcher: NEAR

.CODE
IFDEF AMD64
    KiApcStub PROC PUBLIC
		push rax
		push rcx
        lea rcx, [rsp + 2 * sizeof(QWORD)]
        call ApcHandler 
        pop rcx
        pop rax
        jmp qword ptr [OriginalApcDispatcher]
    KiApcStub ENDP
ELSE
    KiApcStub PROC PUBLIC
        push ebp
        mov ebp, esp
        push eax 
        mov eax, ebp
        add eax, 16
        push eax 
        push [ebp + 8] 
        push [ebp + 4] 
        call ApcHandler@12
        pop eax
        mov esp, ebp
        pop ebp
        jmp dword ptr [OriginalApcDispatcher]
    KiApcStub ENDP
ENDIF
END