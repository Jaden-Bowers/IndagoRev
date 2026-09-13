.code16
.global _start
_start:
  xor %ax,%ax
  mov %ax,%ds
  mov %ax,%es
  mov %ax,%ss
  mov $0x7c00,%sp
  cld
  mov $0x510,%dx
  mov $0x19,%ax
  out %ax,%dx
  inc %dx
  xor %ebx,%ebx
  mov $4,%cx
count:
  in %dx,%al
  shl $8,%ebx
  mov %al,%bl
  loop count
  cmp $128,%ebx
  ja halt
  mov %bx,%bp
entry:
  test %bp,%bp
  jz halt
  dec %bp
  mov $0x8000,%di
  mov $64,%cx
read_entry:
  in %dx,%al
  stosb
  loop read_entry
  mov $name,%si
  mov $0x8008,%di
  mov $(name_end-name),%cx
  repe cmpsb
  jne entry
  mov 0x8004,%ax
  xchg %al,%ah
  mov %ax,%si
  dec %dx
  out %ax,%dx
  inc %dx
  mov $'X',%al
  out %al,%dx
  dec %dx
  mov %si,%ax
  out %ax,%dx
  inc %dx
  in %dx,%al
  mov $0x3f8,%dx
  out %al,%dx
halt:
  cli
  hlt
  jmp halt
name:
  .asciz "opt/indago/transfer"
name_end:
.org 510
.word 0xaa55
