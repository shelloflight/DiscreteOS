; =============================================================================
; Shared 16-bit real-mode helpers for the D-OS bootloader stages.
; Requires: DS = 0. COM1 must be initialised (stage 1 does it).
; =============================================================================

%ifndef COMMON16_INC
%define COMMON16_INC

COM1 equ 0x3F8

; -----------------------------------------------------------------------------
; print: write NUL-terminated string at DS:SI to screen (BIOS) and COM1
; -----------------------------------------------------------------------------
print:
    push ax
    push bx
    push dx
.next:
    lodsb
    test al, al
    jz .done

    mov ah, 0x0E                ; BIOS teletype
    xor bh, bh
    int 0x10

    mov bl, al                  ; keep char while polling the UART
    mov dx, COM1 + 5            ; LSR
.wait_tx:
    in al, dx
    test al, 0x20               ; transmit holding register empty?
    jz .wait_tx
    mov dx, COM1
    mov al, bl
    out dx, al
    jmp .next
.done:
    pop dx
    pop bx
    pop ax
    ret

; -----------------------------------------------------------------------------
; fatal: print DS:SI and halt forever
; -----------------------------------------------------------------------------
fatal:
    call print
.halt:
    cli
    hlt
    jmp .halt

%endif
