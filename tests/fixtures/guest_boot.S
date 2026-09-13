.code16
.global _start
_start:
  xor %ax,%ax
  mov %ax,%ds
  mov %ax,%ss
  mov $0x7c00,%sp
  mov $0x3f8,%dx
  mov $'I',%al
  out %al,%dx
  mov $'G',%al
  out %al,%dx
  mov $'\n',%al
  out %al,%dx
halt:
  cli
  hlt
  jmp halt
.org 510
.word 0xaa55
