# Macros for rebuild instructions
# See https://docs.kernel.org/bpf/instruction-set.html#legacy-bpf-packet-access-instructions
BPF_LD = 0x00
BPF_LDX = 0x01
BPF_ST = 0x02
BPF_STX = 0x03
BPF_ALU = 0x04
BPF_JMP = 0x05
BPF_JMP32 = 0x06
BPF_ALU64 = 0x07

# SOURCE
BPF_K = 0x00  # use 32-bit immediate as source operand
BPF_X = 0x08  # use ‘src_reg’ register as source operand

# BPF_ALU
ALU_ADD = 0x00
ALU_SUB = 0x10
ALU_MUL = 0x20
ALU_DIV = 0x30
ALU_SDIV = 0x30
ALU_OR = 0x40
ALU_AND = 0x50
ALU_RSH = 0x60
ALU_LSH = 0x70
ALU_NEG = 0x80
ALU_MOD = 0x90
ALU_SMOD = 0x90
ALU_XOR = 0xa0
ALU_MOV = 0xb0
ALU_MOVSX = 0xb0  # offset decides the bits
ALU_ARSH = 0xc0
ALU_END = 0xd0

# BPF_BYTE
BPF_TO_LE = 0x00
BPF_TO_BE = 0x08

# BPF_JUMP
JMP_A = 0x00
JMP_EQ = 0x10
JMP_GT = 0x20
JMP_GE = 0x30
JMP_SET = 0x40
JMP_NE = 0x50
JMP_SGT = 0x60
JMP_SGE = 0x70
JMP_CALL = 0x80
JMP_EXIT = 0x90
JMP_LT = 0xa0
JMP_LE = 0xb0
JMP_SLT = 0xc0
JMP_SLE = 0xd0

# BPF_MEMORY
BPF_IMM = 0x00
BPF_ABS = 0x20
BPF_IND = 0x40
BPF_MEM = 0x60
BPF_MEMSX = 0x80
BPF_ATOMIC = 0xc0

# BPF MEMORY SIZE
SIZE_W = 0x00
SIZE_H = 0x08
SIZE_B = 0x10
SIZE_DW = 0x18

# ATOMIC OPERATIONS
ATOMIC_ADD = ALU_ADD
ATOMIC_OR = ALU_OR
ATOMIC_AND = ALU_AND
ATOMIC_XOR = ALU_XOR

# ATOMIC MODIFIER
ATOMIC_FETCH = 0x01
ATOMIC_XCHG = 0xe1
ATOMIC_CMPXCHG = 0xf1