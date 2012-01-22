namespace Distorm3cs
{
    using System;
    using System.Collections.Generic;
    using System.Diagnostics.CodeAnalysis;
    using System.Linq;
    using System.Runtime.InteropServices;
    using System.Text;
    using Logger;

    /// <summary>
    /// A simplified interface to the distorm library.
    /// </summary>
    public class DistormSimple
    {
        #region Constants

#if USE_32_BIT_DECODING
        /// <summary>
        /// A string representation of the target architecture.
        /// </summary>
        private const string ArchitectureString = "32";
#else
        /// <summary>
        /// A string representation of the target architecture.
        /// </summary>
        private const string ArchitectureString = "64";
#endif

        #region Miscellaneous constants

        /// <summary>
        /// No register was defined.
        /// </summary>
        public const byte R_NONE = unchecked((byte)-1);

        /// <summary>
        /// Up to four operands per instruction.
        /// </summary>
        public const byte OPERANDS_NO = 4;

        /// <summary>
        /// The maximum size of the p value of a WString.
        /// </summary>
        public const int MAX_TEXT_SIZE = 48;

        /// <summary>
        /// The default value for the segment value of a Dinst structure.
        /// </summary>
        public const byte SEGMENT_DEFAULT = 0x80;

        /// <summary>
        /// No opcode ID is available.
        /// </summary>
        public const ushort OPCODE_ID_NONE = 0;

        #endregion

        #endregion

        #region Enumerations

        /// <summary>
        /// Different types of operands.
        /// </summary>
        public enum OperandType : byte
        {
            /// <summary>
            /// No type is assigned.
            /// </summary>
            NONE,

            /// <summary>
            /// A register.
            /// </summary>
            REG,

            /// <summary>
            /// An immediate value.
            /// </summary>
            IMM,

            /// <summary>
            /// The first immediate value.
            /// </summary>
            IMM1,

            /// <summary>
            /// The second immediate value.
            /// </summary>
            IMM2,

            /// <summary>
            /// A displacement size.
            /// </summary>
            DISP,

            /// <summary>
            /// Simple memory.
            /// </summary>
            SMEM,

            /// <summary>
            /// Memory.
            /// </summary>
            MEM,

            /// <summary>
            /// Program counter.
            /// </summary>
            PC,

            /// <summary>
            /// A pointer.
            /// </summary>
            PTR
        }

        /// <summary>
        /// Various pieces of information about an instruction's capabilities.
        /// </summary>
        [Flags]
        public enum InstructionFlags : ushort
        {
            /// <summary>
            /// Instruction could not be disassembled.
            /// </summary>
            NOT_DECODABLE = unchecked((ushort)-1),

            /// <summary>
            /// The instruction locks memory access.
            /// </summary>
            LOCK = (1 << 0),

            /// <summary>
            /// The instruction is prefixed with a REPNZ.
            /// </summary>
            REPNZ = (1 << 1),

            /// <summary>
            /// The instruction is prefixed with a REP, this can be a REPZ, it depends on the specific instruction.
            /// </summary>
            REP = (1 << 2),

            /// <summary>
            /// Indicates there is a hint taken for Jcc instructions only.
            /// </summary>
            HINT_TAKEN = (1 << 3),

            /// <summary>
            /// Indicates there is a hint non-taken for Jcc instructions only.
            /// </summary>
            HINT_NOT_TAKEN = (1 << 4),

            /// <summary>
            /// The Imm value is signed extended.
            /// </summary>
            IMM_SIGNED = (1 << 5),

            /// <summary>
            /// The destination operand is writable.
            /// </summary>
            DST_WR = (1 << 6),

            /// <summary>
            /// The instruction uses RIP-relative indirection.
            /// </summary>
            RIP_RELATIVE = (1 << 7)
        }

        /// <summary>
        /// The size of the base register that is being analyzed.
        /// </summary>
        public enum RegisterBase : byte
        {
            /// <summary>
            /// 64-bit registers.
            /// </summary>
            REGS64 = 0,

            /// <summary>
            /// 32-bit registers.
            /// </summary>
            REGS32 = 16,

            /// <summary>
            /// 16 bit registers.
            /// </summary>
            REGS16 = 32,

            /// <summary>
            /// 8 bit registers.
            /// </summary>
            REGS8 = 48,

            /// <summary>
            /// 8 bit extended registers.
            /// </summary>
            REGS8_REX = 64,

            /// <summary>
            /// S registers.
            /// </summary>
            SREGS = 68,

            /// <summary>
            /// Floating point registers.
            /// </summary>
            FPUREGS = 75,

            /// <summary>
            /// MMX registers.
            /// </summary>
            MMXREGS = 83,

            /// <summary>
            /// Streaming SIMD Extensions registers.
            /// </summary>
            SSEREGS = 91,

            /// <summary>
            /// Advanced Vector Extensions registers.
            /// </summary>
            AVXREGS = 107,

            /// <summary>
            /// C registers.
            /// </summary>
            CREGS = 123,

            /// <summary>
            /// D registers.
            /// </summary>
            DREGS = 132,
        }

        /// <summary>
        /// Each mask indicates one of a register-class that is being used in some operand.
        /// </summary>
        [Flags]
        public enum RegisterMask : uint
        {
            /// <summary>
            /// AL, AH, AX, EAX, RAX
            /// </summary>
            AX = 1,

            /// <summary>
            /// CL, CH, CX, ECX, RCX
            /// </summary>
            CX = 2,

            /// <summary>
            /// DL, DH, DX, EDX, RDX
            /// </summary>
            DX = 4,

            /// <summary>
            /// BL, BH, BX, EBX, RBX
            /// </summary>
            BX = 8,

            /// <summary>
            /// SPL, SP, ESP, RSP
            /// </summary>
            SP = 0x10,

            /// <summary>
            /// BPL, BP, EBP, RBP
            /// </summary>
            BP = 0x20,

            /// <summary>
            /// SIL, SI, ESI, RSI
            /// </summary>
            SI = 0x40,

            /// <summary>
            /// DIL, DI, EDI, RDI
            /// </summary>
            DI = 0x80,

            /// <summary>
            /// ST(0) - ST(7)
            /// </summary>
            FPU = 0x100,

            /// <summary>
            /// MM0 - MM7
            /// </summary>
            MMX = 0x200,

            /// <summary>
            /// XMM0 - XMM15
            /// </summary>
            SSE = 0x400,

            /// <summary>
            /// YMM0 - YMM15
            /// </summary>
            AVX = 0x800,

            /// <summary>
            /// CR0, CR2, CR3, CR4, CR8
            /// </summary>
            CR = 0x1000,

            /// <summary>
            /// DR0, DR1, DR2, DR3, DR6, DR7
            /// </summary>
            DR = 0x2000
        }

        /// <summary>
        /// The class of an instruction.
        /// </summary>
        public enum InstructionSetClass : short
        {
            /// <summary>
            /// Integer instructions.
            /// </summary>
            INTEGER = 1,

            /// <summary>
            /// Floating point instructions.
            /// </summary>
            FPU = 2,

            /// <summary>
            /// P6 instructions.
            /// </summary>
            P6 = 3,

            /// <summary>
            /// MMX instructions.
            /// </summary>
            MMX = 4,

            /// <summary>
            /// SSE instructions.
            /// </summary>
            SSE = 5,

            /// <summary>
            /// SSE2 instructions.
            /// </summary>
            SSE2 = 6,

            /// <summary>
            /// SSE3 instructions.
            /// </summary>
            SSE3 = 7,

            /// <summary>
            /// SSSE3 instructions.
            /// </summary>
            SSSE3 = 8,

            /// <summary>
            /// SSE4_1 instructions.
            /// </summary>
            SSE4_1 = 9,

            /// <summary>
            /// SSE4_2 instructions.
            /// </summary>
            SSE4_2 = 10,

            /// <summary>
            /// SSE4_A instructions.
            /// </summary>
            SSE4_A = 11,

            /// <summary>
            /// 3DNow! instructions.
            /// </summary>
            _3DNOW = 12,    // Variables cannot start with a number, so an underscore preceeds it.

            /// <summary>
            /// Extended 3DNow! instructions.
            /// </summary>
            _3DNOWEXT = 13, // Variables cannot start with a number, so an underscore preceeds it.

            /// <summary>
            /// VMX instructions.
            /// </summary>
            VMX = 14,

            /// <summary>
            /// SVM instructions.
            /// </summary>
            SVM = 15,

            /// <summary>
            /// AVX instructions.
            /// </summary>
            AVX = 16,

            /// <summary>
            /// FMA instructions.
            /// </summary>
            FMA = 17,

            /// <summary>
            /// AES instructions.
            /// </summary>
            AES = 18,

            /// <summary>
            /// CMUL instructions.
            /// </summary>
            CLMUL = 19
        }

        /// <summary>
        /// Optional decomposition features.
        /// </summary>
        [Flags]
        public enum DecomposeFeatures : uint
        {
            /// <summary>
            /// No features should be used during decomposition.
            /// </summary>
            NONE = 0,

            /// <summary>
            /// The decoder will limit addresses to a maximum of 16 bits.
            /// </summary>
            MAXIMUM_ADDR16 = 1,

            /// <summary>
            /// The decoder will limit addresses to a maximum of 32 bits.
            /// </summary>
            MAXIMUM_ADDR32 = 2,

            /// <summary>
            /// The decoder will return only flow control instructions (and filter the others internally).
            /// </summary>
            RETURN_FC_ONLY = 4,

            /// <summary>
            /// The decoder will stop and return to the caller when the instruction 'CALL' (near and far) was decoded.
            /// </summary>
            STOP_ON_CALL = 8,

            /// <summary>
            /// The decoder will stop and return to the caller when the instruction 'RET' (near and far) was decoded.
            /// </summary>
            STOP_ON_RET = 0x10,

            /// <summary>
            /// The decoder will stop and return to the caller when the instruction system-call/ret was decoded.
            /// </summary>
            STOP_ON_SYS = 0x20,

            /// <summary>
            /// The decoder will stop and return to the caller when any of the branch 'JMP', (near and far) instructions
            /// were decoded.
            /// </summary>
            STOP_ON_UNC_BRANCH = 0x40,

            /// <summary>
            /// The decoder will stop and return to the caller when any of the conditional branch instruction were decoded.
            /// </summary>
            STOP_ON_CND_BRANCH = 0x80,

            /// <summary>
            /// The decoder will stop and return to the caller when the instruction 'INT' (INT, INT1, INTO, INT 3) was
            /// decoded.
            /// </summary>
            STOP_ON_INT = 0x100,

            /// <summary>
            /// The decoder will stop and return to the caller when any of the 'CMOVxx' instruction was decoded.
            /// </summary>
            STOP_ON_CMOV = 0x200,

            /// <summary>
            /// The decoder will stop and return to the caller when any flow control instruction was decoded.
            /// </summary>
            STOP_ON_FLOW_CONTROL = DecomposeFeatures.STOP_ON_CALL | DecomposeFeatures.STOP_ON_RET |
                                   DecomposeFeatures.STOP_ON_SYS | DecomposeFeatures.STOP_ON_UNC_BRANCH |
                                   DecomposeFeatures.STOP_ON_CND_BRANCH | DecomposeFeatures.STOP_ON_INT |
                                   DecomposeFeatures.STOP_ON_CMOV
        }

        /// <summary>
        /// Flow control of execution.
        /// </summary>
        public enum FlowControl : byte
        {
            /// <summary>
            /// Indicates the instruction is not a flow-control instruction.
            /// </summary>
            NONE = 0,

            /// <summary>
            /// Indicates the instruction is one of: CALL, CALL FAR.
            /// </summary>
            CALL = 1,

            /// <summary>
            /// Indicates the instruction is one of: RET, IRET, RETF.
            /// </summary>
            RET = 2,

            /// <summary>
            /// Indicates the instruction is one of: SYSCALL, SYSRET, SYSENTER, SYSEXIT.
            /// </summary>
            SYS = 3,

            /// <summary>
            /// Indicates the instruction is one of: JMP, JMP FAR.
            /// </summary>
            UNC_BRANCH = 4,

            /// <summary>
            /// Indicates the instruction is one of:
            /// JCXZ, JO, JNO, JB, JAE, JZ, JNZ, JBE, JA, JS, JNS, JP, JNP, JL, JGE, JLE, JG, LOOP, LOOPZ, LOOPNZ.
            /// </summary>
            CND_BRANCH = 5,

            /// <summary>
            /// Indiciates the instruction is one of: INT, INT1, INT 3, INTO, UD2.
            /// </summary>
            INT = 6,

            /// <summary>
            /// Indicates the instruction is one of: CMOVxx.
            /// </summary>
            CMOV = 7
        }

        /// <summary>
        /// The three types of processor types that can be decoded.
        /// </summary>
        public enum DecodeType
        {
            /// <summary>
            /// 16-bit decode type.
            /// </summary>
            Decode16Bits = 0,

            /// <summary>
            /// 32-bit decode type.
            /// </summary>
            Decode32Bits = 1,

            /// <summary>
            /// 64-bit decode type.
            /// </summary>
            Decode64Bits = 2
        }

        /// <summary>
        /// Return code of the decoding function.
        /// </summary>
        public enum DecodeResult
        {
            /// <summary>
            /// Nothing was decoded.
            /// </summary>
            NONE,

            /// <summary>
            /// The decoding was successful.
            /// </summary>
            SUCCESS,

            /// <summary>
            /// There are not enough entries to use in the result array.
            /// </summary>
            MEMORYERR,

            /// <summary>
            /// Input error (null code buffer, invalid decoding mode, etc...).
            /// </summary>
            INPUTERR,

            /// <summary>
            /// The decode result was filtered.
            /// </summary>
            FILTERED
        }

        /// <summary>
        /// Various types of instructions.
        /// </summary>
        [SuppressMessage("Microsoft.StyleCop.CSharp.DocumentationRules", "SA1602:EnumerationItemsMustBeDocumented",
            Justification = "Self-explanatory variables.")]
        public enum InstructionType
        {
            UNDEFINED = 0, AAA = 66, AAD = 389, AAM = 384, AAS = 76, ADC = 31, ADD = 11, ADDPD = 3107,
            ADDPS = 3100, ADDSD = 3121, ADDSS = 3114, ADDSUBPD = 5074, ADDSUBPS = 5084,
            AESDEC = 7882, AESDECLAST = 7899, AESENC = 7840, AESENCLAST = 7857,
            AESIMC = 7823, AESKEYGENASSIST = 8459, AND = 41, ANDNPD = 3018, ANDNPS = 3010,
            ANDPD = 2987, ANDPS = 2980, ARPL = 111, BLENDPD = 8045, BLENDPS = 8026,
            BLENDVPD = 6301, BLENDVPS = 6291, BOUND = 104, BSF = 939, BSR = 4298,
            BSWAP = 965, BT = 872, BTC = 934, BTR = 912, BTS = 887, CALL = 456,
            CALL_FAR = 260, CBW = 228, CDQ = 250, CDQE = 239, CLC = 492, CLD = 512,
            CLFLUSH = 4281, CLGI = 1830, CLI = 502, CLTS = 541, CMC = 487, CMOVA = 694,
            CMOVAE = 663, CMOVB = 656, CMOVBE = 686, CMOVG = 754, CMOVGE = 738,
            CMOVL = 731, CMOVLE = 746, CMOVNO = 648, CMOVNP = 723, CMOVNS = 708,
            CMOVNZ = 678, CMOVO = 641, CMOVP = 716, CMOVS = 701, CMOVZ = 671,
            CMP = 71, CMPEQPD = 4389, CMPEQPS = 4310, CMPEQSD = 4547, CMPEQSS = 4468,
            CMPLEPD = 4407, CMPLEPS = 4328, CMPLESD = 4565, CMPLESS = 4486, CMPLTPD = 4398,
            CMPLTPS = 4319, CMPLTSD = 4556, CMPLTSS = 4477, CMPNEQPD = 4428, CMPNEQPS = 4349,
            CMPNEQSD = 4586, CMPNEQSS = 4507, CMPNLEPD = 4448, CMPNLEPS = 4369,
            CMPNLESD = 4606, CMPNLESS = 4527, CMPNLTPD = 4438, CMPNLTPS = 4359,
            CMPNLTSD = 4596, CMPNLTSS = 4517, CMPORDPD = 4458, CMPORDPS = 4379,
            CMPORDSD = 4616, CMPORDSS = 4537, CMPS = 301, CMPUNORDPD = 4416, CMPUNORDPS = 4337,
            CMPUNORDSD = 4574, CMPUNORDSS = 4495, CMPXCHG = 898, CMPXCHG16B = 5053,
            CMPXCHG8B = 5042, COMISD = 2776, COMISS = 2768, CPUID = 865, CQO = 255,
            CRC32 = 7931, CVTDQ2PD = 5467, CVTDQ2PS = 3304, CVTPD2DQ = 5477, CVTPD2PI = 2678,
            CVTPD2PS = 3230, CVTPI2PD = 2492, CVTPI2PS = 2482, CVTPS2DQ = 3314,
            CVTPS2PD = 3220, CVTPS2PI = 2668, CVTSD2SI = 2698, CVTSD2SS = 3250,
            CVTSI2SD = 2512, CVTSI2SS = 2502, CVTSS2SD = 3240, CVTSS2SI = 2688,
            CVTTPD2DQ = 5456, CVTTPD2PI = 2611, CVTTPS2DQ = 3324, CVTTPS2PI = 2600,
            CVTTSD2SI = 2633, CVTTSS2SI = 2622, CWD = 245, CWDE = 233, DAA = 46,
            DAS = 56, DEC = 86, DIV = 1635, DIVPD = 3496, DIVPS = 3489, DIVSD = 3510,
            DIVSS = 3503, DPPD = 8280, DPPS = 8267, EMMS = 4097, ENTER = 340,
            EXTRACTPS = 8145, EXTRQ = 4133, F2XM1 = 1181, FABS = 1112, FADD = 1012,
            FADDP = 1538, FBLD = 1590, FBSTP = 1596, FCHS = 1106, FCLEX = 5969,
            FCMOVB = 1365, FCMOVBE = 1381, FCMOVE = 1373, FCMOVNB = 1434, FCMOVNBE = 1452,
            FCMOVNE = 1443, FCMOVNU = 1462, FCMOVU = 1390, FCOM = 1024, FCOMI = 1501,
            FCOMIP = 1612, FCOMP = 1030, FCOMPP = 1552, FCOS = 1300, FDECSTP = 1227,
            FDIV = 1050, FDIVP = 1583, FDIVR = 1056, FDIVRP = 1575, FEDISI = 1477,
            FEMMS = 574, FENI = 1471, FFREE = 1516, FIADD = 1306, FICOM = 1320,
            FICOMP = 1327, FIDIV = 1350, FIDIVR = 1357, FILD = 1407, FIMUL = 1313,
            FINCSTP = 1236, FINIT = 5984, FIST = 1421, FISTP = 1427, FISTTP = 1413,
            FISUB = 1335, FISUBR = 1342, FLD = 1063, FLD1 = 1130, FLDCW = 1087,
            FLDENV = 1079, FLDL2E = 1144, FLDL2T = 1136, FLDLG2 = 1159, FLDLN2 = 1167,
            FLDPI = 1152, FLDZ = 1175, FMUL = 1018, FMULP = 1545, FNCLEX = 5961,
            FNINIT = 5976, FNOP = 1100, FNSAVE = 5991, FNSTCW = 5946, FNSTENV = 5929,
            FNSTSW = 6006, FPATAN = 1202, FPREM = 1245, FPREM1 = 1219, FPTAN = 1195,
            FRNDINT = 1277, FRSTOR = 1508, FSAVE = 5999, FSCALE = 1286, FSETPM = 1485,
            FSIN = 1294, FSINCOS = 1268, FSQRT = 1261, FST = 1068, FSTCW = 5954,
            FSTENV = 5938, FSTP = 1073, FSTSW = 6014, FSUB = 1037, FSUBP = 1568,
            FSUBR = 1043, FSUBRP = 1560, FTST = 1118, FUCOM = 1523, FUCOMI = 1493,
            FUCOMIP = 1603, FUCOMP = 1530, FUCOMPP = 1398, FXAM = 1124, FXCH = 1094,
            FXRSTOR = 4234, FXSAVE = 4226, FXTRACT = 1210, FYL2X = 1188, FYL2XP1 = 1252,
            GETSEC = 633, HADDPD = 4158, HADDPS = 4166, HLT = 482, HSUBPD = 4192,
            HSUBPS = 4200, IDIV = 1640, IMUL = 117, IN = 447, INC = 81, INS = 123,
            INSERTPS = 8212, INSERTQ = 4140, INT = 367, INT_3 = 360, INT1 = 476,
            INTO = 372, INVD = 555, INVEPT = 6966, INVLPG = 1716, INVLPGA = 1844,
            INVVPID = 6974, IRET = 378, JA = 166, JAE = 147, JB = 143, JBE = 161,
            JCXZ = 427, JECXZ = 433, JG = 202, JGE = 192, JL = 188, JLE = 197,
            JMP = 462, JMP_FAR = 467, JNO = 138, JNP = 183, JNS = 174, JNZ = 156,
            JO = 134, JP = 179, JRCXZ = 440, JS = 170, JZ = 152, LAHF = 289,
            LAR = 522, LDDQU = 5674, LDMXCSR = 8528, LDS = 335, LEA = 223, LEAVE = 347,
            LES = 330, LFENCE = 4249, LFS = 917, LGDT = 1692, LGS = 922, LIDT = 1698,
            LLDT = 1657, LMSW = 1710, LODS = 313, LOOP = 421, LOOPNZ = 406, LOOPZ = 414,
            LSL = 527, LSS = 907, LTR = 1663, LZCNT = 4303, MASKMOVDQU = 5799,
            MASKMOVQ = 5789, MAXPD = 3556, MAXPS = 3549, MAXSD = 3570, MAXSS = 3563,
            MFENCE = 4265, MINPD = 3436, MINPS = 3429, MINSD = 3450, MINSS = 3443,
            MONITOR = 1760, MOV = 218, MOVAPD = 2456, MOVAPS = 2448, MOVBE = 7924,
            MOVD = 3917, MOVDDUP = 2183, MOVDQ2Q = 5202, MOVDQA = 3943, MOVDQU = 3951,
            MOVHLPS = 2148, MOVHPD = 2342, MOVHPS = 2334, MOVLHPS = 2325, MOVLPD = 2165,
            MOVLPS = 2157, MOVMSKPD = 2812, MOVMSKPS = 2802, MOVNTDQ = 5529, MOVNTDQA = 6577,
            MOVNTI = 957, MOVNTPD = 2553, MOVNTPS = 2544, MOVNTQ = 5521, MOVNTSD = 2571,
            MOVNTSS = 2562, MOVQ = 3923, MOVQ2DQ = 5193, MOVS = 295, MOVSD = 2107,
            MOVSHDUP = 2350, MOVSLDUP = 2173, MOVSS = 2100, MOVSX = 944, MOVSXD = 8597,
            MOVUPD = 2092, MOVUPS = 2084, MOVZX = 927, MPSADBW = 8293, MUL = 1630,
            MULPD = 3167, MULPS = 3160, MULSD = 3181, MULSS = 3174, MWAIT = 1769,
            NEG = 1625, NOP = 581, NOT = 1620, OR = 27, ORPD = 3050, ORPS = 3044,
            OUT = 451, OUTS = 128, PABSB = 6370, PABSD = 6400, PABSW = 6385,
            PACKSSDW = 3846, PACKSSWB = 3678, PACKUSDW = 6598, PACKUSWB = 3756,
            PADDB = 5884, PADDD = 5914, PADDQ = 5161, PADDSB = 5610, PADDSW = 5627,
            PADDUSB = 5300, PADDUSW = 5319, PADDW = 5899, PALIGNR = 8084, PAND = 5287,
            PANDN = 5345, PAUSE = 8605, PAVGB = 5360, PAVGUSB = 2075, PAVGW = 5405,
            PBLENDVB = 6281, PBLENDW = 8064, PCLMULQDQ = 8312, PCMPEQB = 4040,
            PCMPEQD = 4078, PCMPEQQ = 6558, PCMPEQW = 4059, PCMPESTRI = 8391,
            PCMPESTRM = 8368, PCMPGTB = 3699, PCMPGTD = 3737, PCMPGTQ = 6769,
            PCMPGTW = 3718, PCMPISTRI = 8436, PCMPISTRM = 8413, PEXTRB = 8103,
            PEXTRD = 8120, PEXTRQ = 8128, PEXTRW = 4991, PF2ID = 1911, PF2IW = 1904,
            PFACC = 2025, PFADD = 1974, PFCMPEQ = 2032, PFCMPGE = 1935, PFCMPGT = 1981,
            PFMAX = 1990, PFMIN = 1944, PFMUL = 2041, PFNACC = 1918, PFPNACC = 1926,
            PFRCP = 1951, PFRCPIT1 = 1997, PFRCPIT2 = 2048, PFRSQIT1 = 2007, PFRSQRT = 1958,
            PFSUB = 1967, PFSUBR = 2017, PHADDD = 6055, PHADDSW = 6072, PHADDW = 6038,
            PHMINPOSUW = 6941, PHSUBD = 6131, PHSUBSW = 6148, PHSUBW = 6114, PI2FD = 1897,
            PI2FW = 1890, PINSRB = 8195, PINSRD = 8233, PINSRQ = 8241, PINSRW = 4974,
            PMADDUBSW = 6091, PMADDWD = 5753, PMAXSB = 6856, PMAXSD = 6873, PMAXSW = 5644,
            PMAXUB = 5328, PMAXUD = 6907, PMAXUW = 6890, PMINSB = 6788, PMINSD = 6805,
            PMINSW = 5582, PMINUB = 5270, PMINUD = 6839, PMINUW = 6822, PMOVMSKB = 5211,
            PMOVSXBD = 6436, PMOVSXBQ = 6457, PMOVSXBW = 6415, PMOVSXDQ = 6520,
            PMOVSXWD = 6478, PMOVSXWQ = 6499, PMOVZXBD = 6664, PMOVZXBQ = 6685,
            PMOVZXBW = 6643, PMOVZXDQ = 6748, PMOVZXWD = 6706, PMOVZXWQ = 6727,
            PMULDQ = 6541, PMULHRSW = 6218, PMULHRW = 2058, PMULHUW = 5420, PMULHW = 5439,
            PMULLD = 6924, PMULLW = 5176, PMULUDQ = 5734, POP = 22, POPA = 98,
            POPCNT = 4290, POPF = 277, POR = 5599, PREFETCH = 1869, PREFETCHNTA = 2399,
            PREFETCHT0 = 2412, PREFETCHT1 = 2424, PREFETCHT2 = 2436, PREFETCHW = 1879,
            PSADBW = 5772, PSHUFB = 6021, PSHUFD = 3985, PSHUFHW = 3993, PSHUFLW = 4002,
            PSHUFW = 3977, PSIGNB = 6167, PSIGND = 6201, PSIGNW = 6184, PSLLD = 5704,
            PSLLDQ = 8511, PSLLQ = 5719, PSLLW = 5689, PSRAD = 5390, PSRAW = 5375,
            PSRLD = 5131, PSRLDQ = 8494, PSRLQ = 5146, PSRLW = 5116, PSUBB = 5824,
            PSUBD = 5854, PSUBQ = 5869, PSUBSB = 5548, PSUBSW = 5565, PSUBUSB = 5232,
            PSUBUSW = 5251, PSUBW = 5839, PSWAPD = 2067, PTEST = 6311, PUNPCKHBW = 3777,
            PUNPCKHDQ = 3823, PUNPCKHQDQ = 3892, PUNPCKHWD = 3800, PUNPCKLBW = 3609,
            PUNPCKLDQ = 3655, PUNPCKLQDQ = 3867, PUNPCKLWD = 3632, PUSH = 16,
            PUSHA = 91, PUSHF = 270, PXOR = 5661, RCL = 982, RCPPS = 2950, RCPSS = 2957,
            RCR = 987, RDMSR = 600, RDPMC = 607, RDTSC = 593, RDTSCP = 1861,
            RET = 325, RETF = 354, ROL = 972, ROR = 977, ROUNDPD = 7969, ROUNDPS = 7950,
            ROUNDSD = 8007, ROUNDSS = 7988, RSM = 882, RSQRTPS = 2912, RSQRTSS = 2921,
            SAHF = 283, SAL = 1002, SALC = 394, SAR = 1007, SBB = 36, SCAS = 319,
            SETA = 807, SETAE = 780, SETB = 774, SETBE = 800, SETG = 859, SETGE = 845,
            SETL = 839, SETLE = 852, SETNO = 767, SETNP = 832, SETNS = 819, SETNZ = 793,
            SETO = 761, SETP = 826, SETS = 813, SETZ = 787, SFENCE = 4273, SGDT = 1680,
            SHL = 992, SHLD = 876, SHR = 997, SHRD = 892, SHUFPD = 5016, SHUFPS = 5008,
            SIDT = 1686, SKINIT = 1836, SLDT = 1646, SMSW = 1704, SQRTPD = 2852,
            SQRTPS = 2844, SQRTSD = 2868, SQRTSS = 2860, STC = 497, STD = 517,
            STGI = 1824, STI = 507, STMXCSR = 8547, STOS = 307, STR = 1652, SUB = 51,
            SUBPD = 3376, SUBPS = 3369, SUBSD = 3390, SUBSS = 3383, SWAPGS = 1853,
            SYSCALL = 532, SYSENTER = 614, SYSEXIT = 624, SYSRET = 547, TEST = 206,
            UCOMISD = 2739, UCOMISS = 2730, UD2 = 569, UNPCKHPD = 2293, UNPCKHPS = 2283,
            UNPCKLPD = 2251, UNPCKLPS = 2241, VADDPD = 3136, VADDPS = 3128, VADDSD = 3152,
            VADDSS = 3144, VADDSUBPD = 5094, VADDSUBPS = 5105, VAESDEC = 7890,
            VAESDECLAST = 7911, VAESENC = 7848, VAESENCLAST = 7869, VAESIMC = 7831,
            VAESKEYGENASSIST = 8476, VANDNPD = 3035, VANDNPS = 3026, VANDPD = 3002,
            VANDPS = 2994, VBLENDPD = 8054, VBLENDPS = 8035, VBLENDVPD = 8346,
            VBLENDVPS = 8335, VBROADCASTF128 = 6354, VBROADCASTSD = 6340, VBROADCASTSS = 6326,
            VCMPEQPD = 4713, VCMPEQPS = 4626, VCMPEQSD = 4887, VCMPEQSS = 4800,
            VCMPESTRI = 8402, VCMPLEPD = 4733, VCMPLEPS = 4646, VCMPLESD = 4907,
            VCMPLESS = 4820, VCMPLTPD = 4723, VCMPLTPS = 4636, VCMPLTSD = 4897,
            VCMPLTSS = 4810, VCMPNEQPD = 4756, VCMPNEQPS = 4669, VCMPNEQSD = 4930,
            VCMPNEQSS = 4843, VCMPNLEPD = 4778, VCMPNLEPS = 4691, VCMPNLESD = 4952,
            VCMPNLESS = 4865, VCMPNLTPD = 4767, VCMPNLTPS = 4680, VCMPNLTSD = 4941,
            VCMPNLTSS = 4854, VCMPORDPD = 4789, VCMPORDPS = 4702, VCMPORDSD = 4963,
            VCMPORDSS = 4876, VCMPUNORDPD = 4743, VCMPUNORDPS = 4656, VCMPUNORDSD = 4917,
            VCMPUNORDSS = 4830, VCOMISD = 2793, VCOMISS = 2784, VCVTDQ2PD = 5499,
            VCVTDQ2PS = 3335, VCVTPD2DQ = 5510, VCVTPD2PS = 3293, VCVTPS2DQ = 3346,
            VCVTPS2PD = 3282, VCVTSD2SI = 2719, VCVTSD2SS = 3271, VCVTSI2SD = 2533,
            VCVTSI2SS = 2522, VCVTSS2SD = 3260, VCVTSS2SI = 2708, VCVTTPD2DQ = 5487,
            VCVTTPS2DQ = 3357, VCVTTSD2SI = 2656, VCVTTSS2SI = 2644, VDIVPD = 3525,
            VDIVPS = 3517, VDIVSD = 3541, VDIVSS = 3533, VDPPD = 8286, VDPPS = 8273,
            VERR = 1668, VERW = 1674, VEXTRACTF128 = 8181, VEXTRACTPS = 8156,
            VFMADD132PD = 7060, VFMADD132PS = 7047, VFMADD132SD = 7086, VFMADD132SS = 7073,
            VFMADD213PD = 7340, VFMADD213PS = 7327, VFMADD213SD = 7366, VFMADD213SS = 7353,
            VFMADD231PD = 7620, VFMADD231PS = 7607, VFMADD231SD = 7646, VFMADD231SS = 7633,
            VFMADDSUB132PD = 6999, VFMADDSUB132PS = 6983, VFMADDSUB213PD = 7279,
            VFMADDSUB213PS = 7263, VFMADDSUB231PD = 7559, VFMADDSUB231PS = 7543,
            VFMSUB132PD = 7112, VFMSUB132PS = 7099, VFMSUB132SD = 7138, VFMSUB132SS = 7125,
            VFMSUB213PD = 7392, VFMSUB213PS = 7379, VFMSUB213SD = 7418, VFMSUB213SS = 7405,
            VFMSUB231PD = 7672, VFMSUB231PS = 7659, VFMSUB231SD = 7698, VFMSUB231SS = 7685,
            VFMSUBADD132PD = 7031, VFMSUBADD132PS = 7015, VFMSUBADD213PD = 7311,
            VFMSUBADD213PS = 7295, VFMSUBADD231PD = 7591, VFMSUBADD231PS = 7575,
            VFNMADD132PD = 7165, VFNMADD132PS = 7151, VFNMADD132SD = 7193, VFNMADD132SS = 7179,
            VFNMADD213PD = 7445, VFNMADD213PS = 7431, VFNMADD213SD = 7473, VFNMADD213SS = 7459,
            VFNMADD231PD = 7725, VFNMADD231PS = 7711, VFNMADD231SD = 7753, VFNMADD231SS = 7739,
            VFNMSUB132PD = 7221, VFNMSUB132PS = 7207, VFNMSUB132SD = 7249, VFNMSUB132SS = 7235,
            VFNMSUB213PD = 7501, VFNMSUB213PS = 7487, VFNMSUB213SD = 7529, VFNMSUB213SS = 7515,
            VFNMSUB231PD = 7781, VFNMSUB231PS = 7767, VFNMSUB231SD = 7809, VFNMSUB231SS = 7795,
            VHADDPD = 4174, VHADDPS = 4183, VHSUBPD = 4208, VHSUBPS = 4217, VINSERTF128 = 8168,
            VINSERTPS = 8222, VLDDQU = 5681, VLDMXCSR = 8537, VMASKMOVDQU = 5811,
            VMASKMOVPD = 6631, VMASKMOVPS = 6619, VMAXPD = 3585, VMAXPS = 3577,
            VMAXSD = 3601, VMAXSS = 3593, VMCALL = 1724, VMCLEAR = 8575, VMINPD = 3465,
            VMINPS = 3457, VMINSD = 3481, VMINSS = 3473, VMLAUNCH = 1732, VMLOAD = 1808,
            VMMCALL = 1799, VMOVAPD = 2473, VMOVAPS = 2464, VMOVD = 3929, VMOVDDUP = 2231,
            VMOVDQA = 3959, VMOVDQU = 3968, VMOVHLPS = 2192, VMOVHPD = 2379, VMOVHPS = 2370,
            VMOVLHPS = 2360, VMOVLPD = 2211, VMOVLPS = 2202, VMOVMSKPD = 2833,
            VMOVMSKPS = 2822, VMOVNTDQ = 5538, VMOVNTDQA = 6587, VMOVNTPD = 2590,
            VMOVNTPS = 2580, VMOVQ = 3936, VMOVSD = 2122, VMOVSHDUP = 2388, VMOVSLDUP = 2220,
            VMOVSS = 2114, VMOVUPD = 2139, VMOVUPS = 2130, VMPSADBW = 8302, VMPTRLD = 8566,
            VMPTRST = 5065, VMREAD = 4125, VMRESUME = 1742, VMRUN = 1792, VMSAVE = 1816,
            VMULPD = 3196, VMULPS = 3188, VMULSD = 3212, VMULSS = 3204, VMWRITE = 4149,
            VMXOFF = 1752, VMXON = 8584, VORPD = 3063, VORPS = 3056, VPABSB = 6377,
            VPABSD = 6407, VPABSW = 6392, VPACKSSDW = 3856, VPACKSSWB = 3688,
            VPACKUSDW = 6608, VPACKUSWB = 3766, VPADDB = 5891, VPADDD = 5921,
            VPADDQ = 5168, VPADDSB = 5618, VPADDSW = 5635, VPADDUSW = 5309, VPADDW = 5906,
            VPALIGNR = 8093, VPAND = 5293, VPANDN = 5352, VPAVGB = 5367, VPAVGW = 5412,
            VPBLENDVB = 8357, VPBLENDVW = 8073, VPCLMULQDQ = 8323, VPCMPEQB = 4049,
            VPCMPEQD = 4087, VPCMPEQQ = 6567, VPCMPEQW = 4068, VPCMPESTRM = 8379,
            VPCMPGTB = 3708, VPCMPGTD = 3746, VPCMPGTQ = 6778, VPCMPGTW = 3727,
            VPCMPISTRI = 8447, VPCMPISTRM = 8424, VPERM2F128 = 7938, VPERMILPD = 6250,
            VPERMILPS = 6239, VPEXTRB = 8111, VPEXTRD = 8136, VPEXTRW = 4999,
            VPHADDD = 6063, VPHADDSW = 6081, VPHADDW = 6046, VPHMINPOSUW = 6953,
            VPHSUBD = 6139, VPHSUBSW = 6157, VPHSUBW = 6122, VPINSRB = 8203, VPINSRD = 8249,
            VPINSRQ = 8258, VPINSRW = 4982, VPMADDUBSW = 6102, VPMADDWD = 5762,
            VPMAXSB = 6864, VPMAXSD = 6881, VPMAXSW = 5652, VPMAXUB = 5336, VPMAXUD = 6915,
            VPMAXUW = 6898, VPMINSB = 6796, VPMINSD = 6813, VPMINSW = 5590, VPMINUB = 5278,
            VPMINUD = 6847, VPMINUW = 6830, VPMOVMSKB = 5221, VPMOVSXBD = 6446,
            VPMOVSXBQ = 6467, VPMOVSXBW = 6425, VPMOVSXDQ = 6530, VPMOVSXWD = 6488,
            VPMOVSXWQ = 6509, VPMOVZXBD = 6674, VPMOVZXBQ = 6695, VPMOVZXBW = 6653,
            VPMOVZXDQ = 6758, VPMOVZXWD = 6716, VPMOVZXWQ = 6737, VPMULDQ = 6549,
            VPMULHRSW = 6228, VPMULHUW = 5429, VPMULHW = 5447, VPMULLD = 6932,
            VPMULLW = 5184, VPMULUDQ = 5743, VPOR = 5604, VPSADBW = 5780, VPSHUFB = 6029,
            VPSHUFD = 4011, VPSHUFHW = 4020, VPSHUFLW = 4030, VPSIGNB = 6175,
            VPSIGND = 6209, VPSIGNW = 6192, VPSLLD = 5711, VPSLLDQ = 8519, VPSLLQ = 5726,
            VPSLLW = 5696, VPSRAD = 5397, VPSRAW = 5382, VPSRLD = 5138, VPSRLDQ = 8502,
            VPSRLQ = 5153, VPSRLW = 5123, VPSUBB = 5831, VPSUBD = 5861, VPSUBQ = 5876,
            VPSUBSB = 5556, VPSUBSW = 5573, VPSUBUSB = 5241, VPSUBUSW = 5260,
            VPSUBW = 5846, VPTEST = 6318, VPTESTPD = 6271, VPTESTPS = 6261, VPUNPCKHBW = 3788,
            VPUNPCKHDQ = 3834, VPUNPCKHQDQ = 3904, VPUNPCKHWD = 3811, VPUNPCKLBW = 3620,
            VPUNPCKLDQ = 3666, VPUNPCKLQDQ = 3879, VPUNPCKLWD = 3643, VPXOR = 5667,
            VRCPPS = 2972, VRCPSS = 2964, VROUNDPD = 7978, VROUNDPS = 7959, VROUNDSD = 8016,
            VROUNDSS = 7997, VRSQRTPS = 2940, VRSQRTSS = 2930, VSHUFPD = 5033,
            VSHUFPS = 5024, VSQRTPD = 2903, VSQRTPS = 2894, VSQRTSD = 2885, VSQRTSS = 2876,
            VSTMXCSR = 8556, VSUBPD = 3405, VSUBPS = 3397, VSUBSD = 3421, VSUBSS = 3413,
            VUCOMISD = 2758, VUCOMISS = 2748, VUNPCKHPD = 2314, VUNPCKHPS = 2303,
            VUNPCKLPD = 2272, VUNPCKLPS = 2261, VXORPD = 3092, VXORPS = 3084,
            VZEROALL = 4115, VZEROUPPER = 4103, WAIT = 8591, WBINVD = 561, WRMSR = 586,
            XADD = 951, XAVE = 4243, XCHG = 212, XGETBV = 1776, XLAT = 400, XOR = 61,
            XORPD = 3077, XORPS = 3070, XRSTOR = 4257, XSETBV = 1784
        }

        /// <summary>
        /// Various types of registers.
        /// </summary>
        [SuppressMessage("Microsoft.StyleCop.CSharp.DocumentationRules", "SA1602:EnumerationItemsMustBeDocumented",
            Justification = "Self-explanatory variables.")]
        public enum RegisterType
        {
            RAX, RCX, RDX, RBX, RSP, RBP, RSI, RDI, R8, R9, R10, R11, R12, R13, R14, R15,
            EAX, ECX, EDX, EBX, ESP, EBP, ESI, EDI, R8D, R9D, R10D, R11D, R12D, R13D, R14D, R15D,
            AX, CX, DX, BX, SP, BP, SI, DI, R8W, R9W, R10W, R11W, R12W, R13W, R14W, R15W,
            AL, CL, DL, BL, AH, CH, DH, BH, R8B, R9B, R10B, R11B, R12B, R13B, R14B, R15B,
            SPL, BPL, SIL, DIL,
            ES, CS, SS, DS, FS, GS,
            RIP,
            ST0, ST1, ST2, ST3, ST4, ST5, ST6, ST7,
            MM0, MM1, MM2, MM3, MM4, MM5, MM6, MM7,
            XMM0, XMM1, XMM2, XMM3, XMM4, XMM5, XMM6, XMM7, XMM8, XMM9, XMM10, XMM11, XMM12, XMM13, XMM14, XMM15,
            YMM0, YMM1, YMM2, YMM3, YMM4, YMM5, YMM6, YMM7, YMM8, YMM9, YMM10, YMM11, YMM12, YMM13, YMM14, YMM15,
            CR0, UNUSED0, CR2, CR3, CR4, UNUSED1, UNUSED2, UNUSED3, CR8,
            DR0, DR1, DR2, DR3, UNUSED4, UNUSED5, DR6, DR7
        }

        #endregion

        #region Properties

        #region Mnemonics

        /// <summary>
        /// Gets the set of mneumonics, represented as a single character array.
        /// </summary>
        public static char[] MNEMONICS
        {
            get
            {
                return (
                    "\x09" + "UNDEFINED\0" + "\x03" + "ADD\0" + "\x04" + "PUSH\0" + "\x03" + "POP\0" + "\x02" + "OR\0" +
                    "\x03" + "ADC\0" + "\x03" + "SBB\0" + "\x03" + "AND\0" + "\x03" + "DAA\0" + "\x03" + "SUB\0" +
                    "\x03" + "DAS\0" + "\x03" + "XOR\0" + "\x03" + "AAA\0" + "\x03" + "CMP\0" + "\x03" + "AAS\0" +
                    "\x03" + "INC\0" + "\x03" + "DEC\0" + "\x05" + "PUSHA\0" + "\x04" + "POPA\0" + "\x05" + "BOUND\0" +
                    "\x04" + "ARPL\0" + "\x04" + "IMUL\0" + "\x03" + "INS\0" + "\x04" + "OUTS\0" + "\x02" + "JO\0" +
                    "\x03" + "JNO\0" + "\x02" + "JB\0" + "\x03" + "JAE\0" + "\x02" + "JZ\0" + "\x03" + "JNZ\0" + "\x03" + "JBE\0" +
                    "\x02" + "JA\0" + "\x02" + "JS\0" + "\x03" + "JNS\0" + "\x02" + "JP\0" + "\x03" + "JNP\0" + "\x02" + "JL\0" +
                    "\x03" + "JGE\0" + "\x03" + "JLE\0" + "\x02" + "JG\0" + "\x04" + "TEST\0" + "\x04" + "XCHG\0" +
                    "\x03" + "MOV\0" + "\x03" + "LEA\0" + "\x03" + "CBW\0" + "\x04" + "CWDE\0" + "\x04" + "CDQE\0" +
                    "\x03" + "CWD\0" + "\x03" + "CDQ\0" + "\x03" + "CQO\0" + "\x08" + "CALL FAR\0" + "\x05" + "PUSHF\0" +
                    "\x04" + "POPF\0" + "\x04" + "SAHF\0" + "\x04" + "LAHF\0" + "\x04" + "MOVS\0" + "\x04" + "CMPS\0" +
                    "\x04" + "STOS\0" + "\x04" + "LODS\0" + "\x04" + "SCAS\0" + "\x03" + "RET\0" + "\x03" + "LES\0" +
                    "\x03" + "LDS\0" + "\x05" + "ENTER\0" + "\x05" + "LEAVE\0" + "\x04" + "RETF\0" + "\x05" + "INT 3\0" +
                    "\x03" + "INT\0" + "\x04" + "INTO\0" + "\x04" + "IRET\0" + "\x03" + "AAM\0" + "\x03" + "AAD\0" +
                    "\x04" + "SALC\0" + "\x04" + "XLAT\0" + "\x06" + "LOOPNZ\0" + "\x05" + "LOOPZ\0" + "\x04" + "LOOP\0" +
                    "\x04" + "JCXZ\0" + "\x05" + "JECXZ\0" + "\x05" + "JRCXZ\0" + "\x02" + "IN\0" + "\x03" + "OUT\0" +
                    "\x04" + "CALL\0" + "\x03" + "JMP\0" + "\x07" + "JMP FAR\0" + "\x04" + "INT1\0" + "\x03" + "HLT\0" +
                    "\x03" + "CMC\0" + "\x03" + "CLC\0" + "\x03" + "STC\0" + "\x03" + "CLI\0" + "\x03" + "STI\0" +
                    "\x03" + "CLD\0" + "\x03" + "STD\0" + "\x03" + "LAR\0" + "\x03" + "LSL\0" + "\x07" + "SYSCALL\0" +
                    "\x04" + "CLTS\0" + "\x06" + "SYSRET\0" + "\x04" + "INVD\0" + "\x06" + "WBINVD\0" + "\x03" + "UD2\0" +
                    "\x05" + "FEMMS\0" + "\x03" + "NOP\0" + "\x05" + "WRMSR\0" + "\x05" + "RDTSC\0" + "\x05" + "RDMSR\0" +
                    "\x05" + "RDPMC\0" + "\x08" + "SYSENTER\0" + "\x07" + "SYSEXIT\0" + "\x06" + "GETSEC\0" + "\x05" + "CMOVO\0" +
                    "\x06" + "CMOVNO\0" + "\x05" + "CMOVB\0" + "\x06" + "CMOVAE\0" + "\x05" + "CMOVZ\0" + "\x06" + "CMOVNZ\0" +
                    "\x06" + "CMOVBE\0" + "\x05" + "CMOVA\0" + "\x05" + "CMOVS\0" + "\x06" + "CMOVNS\0" + "\x05" + "CMOVP\0" +
                    "\x06" + "CMOVNP\0" + "\x05" + "CMOVL\0" + "\x06" + "CMOVGE\0" + "\x06" + "CMOVLE\0" + "\x05" + "CMOVG\0" +
                    "\x04" + "SETO\0" + "\x05" + "SETNO\0" + "\x04" + "SETB\0" + "\x05" + "SETAE\0" + "\x04" + "SETZ\0" +
                    "\x05" + "SETNZ\0" + "\x05" + "SETBE\0" + "\x04" + "SETA\0" + "\x04" + "SETS\0" + "\x05" + "SETNS\0" +
                    "\x04" + "SETP\0" + "\x05" + "SETNP\0" + "\x04" + "SETL\0" + "\x05" + "SETGE\0" + "\x05" + "SETLE\0" +
                    "\x04" + "SETG\0" + "\x05" + "CPUID\0" + "\x02" + "BT\0" + "\x04" + "SHLD\0" + "\x03" + "RSM\0" +
                    "\x03" + "BTS\0" + "\x04" + "SHRD\0" + "\x07" + "CMPXCHG\0" + "\x03" + "LSS\0" + "\x03" + "BTR\0" +
                    "\x03" + "LFS\0" + "\x03" + "LGS\0" + "\x05" + "MOVZX\0" + "\x03" + "BTC\0" + "\x03" + "BSF\0" +
                    "\x05" + "MOVSX\0" + "\x04" + "XADD\0" + "\x06" + "MOVNTI\0" + "\x05" + "BSWAP\0" + "\x03" + "ROL\0" +
                    "\x03" + "ROR\0" + "\x03" + "RCL\0" + "\x03" + "RCR\0" + "\x03" + "SHL\0" + "\x03" + "SHR\0" +
                    "\x03" + "SAL\0" + "\x03" + "SAR\0" + "\x04" + "FADD\0" + "\x04" + "FMUL\0" + "\x04" + "FCOM\0" +
                    "\x05" + "FCOMP\0" + "\x04" + "FSUB\0" + "\x05" + "FSUBR\0" + "\x04" + "FDIV\0" + "\x05" + "FDIVR\0" +
                    "\x03" + "FLD\0" + "\x03" + "FST\0" + "\x04" + "FSTP\0" + "\x06" + "FLDENV\0" + "\x05" + "FLDCW\0" +
                    "\x04" + "FXCH\0" + "\x04" + "FNOP\0" + "\x04" + "FCHS\0" + "\x04" + "FABS\0" + "\x04" + "FTST\0" +
                    "\x04" + "FXAM\0" + "\x04" + "FLD1\0" + "\x06" + "FLDL2T\0" + "\x06" + "FLDL2E\0" + "\x05" + "FLDPI\0" +
                    "\x06" + "FLDLG2\0" + "\x06" + "FLDLN2\0" + "\x04" + "FLDZ\0" + "\x05" + "F2XM1\0" + "\x05" + "FYL2X\0" +
                    "\x05" + "FPTAN\0" + "\x06" + "FPATAN\0" + "\x07" + "FXTRACT\0" + "\x06" + "FPREM1\0" + "\x07" + "FDECSTP\0" +
                    "\x07" + "FINCSTP\0" + "\x05" + "FPREM\0" + "\x07" + "FYL2XP1\0" + "\x05" + "FSQRT\0" + "\x07" + "FSINCOS\0" +
                    "\x07" + "FRNDINT\0" + "\x06" + "FSCALE\0" + "\x04" + "FSIN\0" + "\x04" + "FCOS\0" + "\x05" + "FIADD\0" +
                    "\x05" + "FIMUL\0" + "\x05" + "FICOM\0" + "\x06" + "FICOMP\0" + "\x05" + "FISUB\0" + "\x06" + "FISUBR\0" +
                    "\x05" + "FIDIV\0" + "\x06" + "FIDIVR\0" + "\x06" + "FCMOVB\0" + "\x06" + "FCMOVE\0" + "\x07" + "FCMOVBE\0" +
                    "\x06" + "FCMOVU\0" + "\x07" + "FUCOMPP\0" + "\x04" + "FILD\0" + "\x06" + "FISTTP\0" + "\x04" + "FIST\0" +
                    "\x05" + "FISTP\0" + "\x07" + "FCMOVNB\0" + "\x07" + "FCMOVNE\0" + "\x08" + "FCMOVNBE\0" +
                    "\x07" + "FCMOVNU\0" + "\x04" + "FENI\0" + "\x06" + "FEDISI\0" + "\x06" + "FSETPM\0" + "\x06" + "FUCOMI\0" +
                    "\x05" + "FCOMI\0" + "\x06" + "FRSTOR\0" + "\x05" + "FFREE\0" + "\x05" + "FUCOM\0" + "\x06" + "FUCOMP\0" +
                    "\x05" + "FADDP\0" + "\x05" + "FMULP\0" + "\x06" + "FCOMPP\0" + "\x06" + "FSUBRP\0" + "\x05" + "FSUBP\0" +
                    "\x06" + "FDIVRP\0" + "\x05" + "FDIVP\0" + "\x04" + "FBLD\0" + "\x05" + "FBSTP\0" + "\x07" + "FUCOMIP\0" +
                    "\x06" + "FCOMIP\0" + "\x03" + "NOT\0" + "\x03" + "NEG\0" + "\x03" + "MUL\0" + "\x03" + "DIV\0" +
                    "\x04" + "IDIV\0" + "\x04" + "SLDT\0" + "\x03" + "STR\0" + "\x04" + "LLDT\0" + "\x03" + "LTR\0" +
                    "\x04" + "VERR\0" + "\x04" + "VERW\0" + "\x04" + "SGDT\0" + "\x04" + "SIDT\0" + "\x04" + "LGDT\0" +
                    "\x04" + "LIDT\0" + "\x04" + "SMSW\0" + "\x04" + "LMSW\0" + "\x06" + "INVLPG\0" + "\x06" + "VMCALL\0" +
                    "\x08" + "VMLAUNCH\0" + "\x08" + "VMRESUME\0" + "\x06" + "VMXOFF\0" + "\x07" + "MONITOR\0" +
                    "\x05" + "MWAIT\0" + "\x06" + "XGETBV\0" + "\x06" + "XSETBV\0" + "\x05" + "VMRUN\0" + "\x07" + "VMMCALL\0" +
                    "\x06" + "VMLOAD\0" + "\x06" + "VMSAVE\0" + "\x04" + "STGI\0" + "\x04" + "CLGI\0" + "\x06" + "SKINIT\0" +
                    "\x07" + "INVLPGA\0" + "\x06" + "SWAPGS\0" + "\x06" + "RDTSCP\0" + "\x08" + "PREFETCH\0" +
                    "\x09" + "PREFETCHW\0" + "\x05" + "PI2FW\0" + "\x05" + "PI2FD\0" + "\x05" + "PF2IW\0" + "\x05" + "PF2ID\0" +
                    "\x06" + "PFNACC\0" + "\x07" + "PFPNACC\0" + "\x07" + "PFCMPGE\0" + "\x05" + "PFMIN\0" + "\x05" + "PFRCP\0" +
                    "\x07" + "PFRSQRT\0" + "\x05" + "PFSUB\0" + "\x05" + "PFADD\0" + "\x07" + "PFCMPGT\0" + "\x05" + "PFMAX\0" +
                    "\x08" + "PFRCPIT1\0" + "\x08" + "PFRSQIT1\0" + "\x06" + "PFSUBR\0" + "\x05" + "PFACC\0" +
                    "\x07" + "PFCMPEQ\0" + "\x05" + "PFMUL\0" + "\x08" + "PFRCPIT2\0" + "\x07" + "PMULHRW\0" +
                    "\x06" + "PSWAPD\0" + "\x07" + "PAVGUSB\0" + "\x06" + "MOVUPS\0" + "\x06" + "MOVUPD\0" + "\x05" + "MOVSS\0" +
                    "\x05" + "MOVSD\0" + "\x06" + "VMOVSS\0" + "\x06" + "VMOVSD\0" + "\x07" + "VMOVUPS\0" + "\x07" + "VMOVUPD\0" +
                    "\x07" + "MOVHLPS\0" + "\x06" + "MOVLPS\0" + "\x06" + "MOVLPD\0" + "\x08" + "MOVSLDUP\0" +
                    "\x07" + "MOVDDUP\0" + "\x08" + "VMOVHLPS\0" + "\x07" + "VMOVLPS\0" + "\x07" + "VMOVLPD\0" +
                    "\x09" + "VMOVSLDUP\0" + "\x08" + "VMOVDDUP\0" + "\x08" + "UNPCKLPS\0" + "\x08" + "UNPCKLPD\0" +
                    "\x09" + "VUNPCKLPS\0" + "\x09" + "VUNPCKLPD\0" + "\x08" + "UNPCKHPS\0" + "\x08" + "UNPCKHPD\0" +
                    "\x09" + "VUNPCKHPS\0" + "\x09" + "VUNPCKHPD\0" + "\x07" + "MOVLHPS\0" + "\x06" + "MOVHPS\0" +
                    "\x06" + "MOVHPD\0" + "\x08" + "MOVSHDUP\0" + "\x08" + "VMOVLHPS\0" + "\x07" + "VMOVHPS\0" +
                    "\x07" + "VMOVHPD\0" + "\x09" + "VMOVSHDUP\0" + "\x0b" + "PREFETCHNTA\0" + "\x0a" + "PREFETCHT0\0" +
                    "\x0a" + "PREFETCHT1\0" + "\x0a" + "PREFETCHT2\0" + "\x06" + "MOVAPS\0" + "\x06" + "MOVAPD\0" +
                    "\x07" + "VMOVAPS\0" + "\x07" + "VMOVAPD\0" + "\x08" + "CVTPI2PS\0" + "\x08" + "CVTPI2PD\0" +
                    "\x08" + "CVTSI2SS\0" + "\x08" + "CVTSI2SD\0" + "\x09" + "VCVTSI2SS\0" + "\x09" + "VCVTSI2SD\0" +
                    "\x07" + "MOVNTPS\0" + "\x07" + "MOVNTPD\0" + "\x07" + "MOVNTSS\0" + "\x07" + "MOVNTSD\0" +
                    "\x08" + "VMOVNTPS\0" + "\x08" + "VMOVNTPD\0" + "\x09" + "CVTTPS2PI\0" + "\x09" + "CVTTPD2PI\0" +
                    "\x09" + "CVTTSS2SI\0" + "\x09" + "CVTTSD2SI\0" + "\x0a" + "VCVTTSS2SI\0" + "\x0a" + "VCVTTSD2SI\0" +
                    "\x08" + "CVTPS2PI\0" + "\x08" + "CVTPD2PI\0" + "\x08" + "CVTSS2SI\0" + "\x08" + "CVTSD2SI\0" +
                    "\x09" + "VCVTSS2SI\0" + "\x09" + "VCVTSD2SI\0" + "\x07" + "UCOMISS\0" + "\x07" + "UCOMISD\0" +
                    "\x08" + "VUCOMISS\0" + "\x08" + "VUCOMISD\0" + "\x06" + "COMISS\0" + "\x06" + "COMISD\0" +
                    "\x07" + "VCOMISS\0" + "\x07" + "VCOMISD\0" + "\x08" + "MOVMSKPS\0" + "\x08" + "MOVMSKPD\0" +
                    "\x09" + "VMOVMSKPS\0" + "\x09" + "VMOVMSKPD\0" + "\x06" + "SQRTPS\0" + "\x06" + "SQRTPD\0" +
                    "\x06" + "SQRTSS\0" + "\x06" + "SQRTSD\0" + "\x07" + "VSQRTSS\0" + "\x07" + "VSQRTSD\0" + "\x07" + "VSQRTPS\0" +
                    "\x07" + "VSQRTPD\0" + "\x07" + "RSQRTPS\0" + "\x07" + "RSQRTSS\0" + "\x08" + "VRSQRTSS\0" +
                    "\x08" + "VRSQRTPS\0" + "\x05" + "RCPPS\0" + "\x05" + "RCPSS\0" + "\x06" + "VRCPSS\0" + "\x06" + "VRCPPS\0" +
                    "\x05" + "ANDPS\0" + "\x05" + "ANDPD\0" + "\x06" + "VANDPS\0" + "\x06" + "VANDPD\0" + "\x06" + "ANDNPS\0" +
                    "\x06" + "ANDNPD\0" + "\x07" + "VANDNPS\0" + "\x07" + "VANDNPD\0" + "\x04" + "ORPS\0" + "\x04" + "ORPD\0" +
                    "\x05" + "VORPS\0" + "\x05" + "VORPD\0" + "\x05" + "XORPS\0" + "\x05" + "XORPD\0" + "\x06" + "VXORPS\0" +
                    "\x06" + "VXORPD\0" + "\x05" + "ADDPS\0" + "\x05" + "ADDPD\0" + "\x05" + "ADDSS\0" + "\x05" + "ADDSD\0" +
                    "\x06" + "VADDPS\0" + "\x06" + "VADDPD\0" + "\x06" + "VADDSS\0" + "\x06" + "VADDSD\0" + "\x05" + "MULPS\0" +
                    "\x05" + "MULPD\0" + "\x05" + "MULSS\0" + "\x05" + "MULSD\0" + "\x06" + "VMULPS\0" + "\x06" + "VMULPD\0" +
                    "\x06" + "VMULSS\0" + "\x06" + "VMULSD\0" + "\x08" + "CVTPS2PD\0" + "\x08" + "CVTPD2PS\0" +
                    "\x08" + "CVTSS2SD\0" + "\x08" + "CVTSD2SS\0" + "\x09" + "VCVTSS2SD\0" + "\x09" + "VCVTSD2SS\0" +
                    "\x09" + "VCVTPS2PD\0" + "\x09" + "VCVTPD2PS\0" + "\x08" + "CVTDQ2PS\0" + "\x08" + "CVTPS2DQ\0" +
                    "\x09" + "CVTTPS2DQ\0" + "\x09" + "VCVTDQ2PS\0" + "\x09" + "VCVTPS2DQ\0" + "\x0a" + "VCVTTPS2DQ\0" +
                    "\x05" + "SUBPS\0" + "\x05" + "SUBPD\0" + "\x05" + "SUBSS\0" + "\x05" + "SUBSD\0" + "\x06" + "VSUBPS\0" +
                    "\x06" + "VSUBPD\0" + "\x06" + "VSUBSS\0" + "\x06" + "VSUBSD\0" + "\x05" + "MINPS\0" + "\x05" + "MINPD\0" +
                    "\x05" + "MINSS\0" + "\x05" + "MINSD\0" + "\x06" + "VMINPS\0" + "\x06" + "VMINPD\0" + "\x06" + "VMINSS\0" +
                    "\x06" + "VMINSD\0" + "\x05" + "DIVPS\0" + "\x05" + "DIVPD\0" + "\x05" + "DIVSS\0" + "\x05" + "DIVSD\0" +
                    "\x06" + "VDIVPS\0" + "\x06" + "VDIVPD\0" + "\x06" + "VDIVSS\0" + "\x06" + "VDIVSD\0" + "\x05" + "MAXPS\0" +
                    "\x05" + "MAXPD\0" + "\x05" + "MAXSS\0" + "\x05" + "MAXSD\0" + "\x06" + "VMAXPS\0" + "\x06" + "VMAXPD\0" +
                    "\x06" + "VMAXSS\0" + "\x06" + "VMAXSD\0" + "\x09" + "PUNPCKLBW\0" + "\x0a" + "VPUNPCKLBW\0" +
                    "\x09" + "PUNPCKLWD\0" + "\x0a" + "VPUNPCKLWD\0" + "\x09" + "PUNPCKLDQ\0" + "\x0a" + "VPUNPCKLDQ\0" +
                    "\x08" + "PACKSSWB\0" + "\x09" + "VPACKSSWB\0" + "\x07" + "PCMPGTB\0" + "\x08" + "VPCMPGTB\0" +
                    "\x07" + "PCMPGTW\0" + "\x08" + "VPCMPGTW\0" + "\x07" + "PCMPGTD\0" + "\x08" + "VPCMPGTD\0" +
                    "\x08" + "PACKUSWB\0" + "\x09" + "VPACKUSWB\0" + "\x09" + "PUNPCKHBW\0" + "\x0a" + "VPUNPCKHBW\0" +
                    "\x09" + "PUNPCKHWD\0" + "\x0a" + "VPUNPCKHWD\0" + "\x09" + "PUNPCKHDQ\0" + "\x0a" + "VPUNPCKHDQ\0" +
                    "\x08" + "PACKSSDW\0" + "\x09" + "VPACKSSDW\0" + "\x0a" + "PUNPCKLQDQ\0" + "\x0b" + "VPUNPCKLQDQ\0" +
                    "\x0a" + "PUNPCKHQDQ\0" + "\x0b" + "VPUNPCKHQDQ\0" + "\x04" + "MOVD\0" + "\x04" + "MOVQ\0" +
                    "\x05" + "VMOVD\0" + "\x05" + "VMOVQ\0" + "\x06" + "MOVDQA\0" + "\x06" + "MOVDQU\0" + "\x07" + "VMOVDQA\0" +
                    "\x07" + "VMOVDQU\0" + "\x06" + "PSHUFW\0" + "\x06" + "PSHUFD\0" + "\x07" + "PSHUFHW\0" + "\x07" + "PSHUFLW\0" +
                    "\x07" + "VPSHUFD\0" + "\x08" + "VPSHUFHW\0" + "\x08" + "VPSHUFLW\0" + "\x07" + "PCMPEQB\0" +
                    "\x08" + "VPCMPEQB\0" + "\x07" + "PCMPEQW\0" + "\x08" + "VPCMPEQW\0" + "\x07" + "PCMPEQD\0" +
                    "\x08" + "VPCMPEQD\0" + "\x04" + "EMMS\0" + "\x0a" + "VZEROUPPER\0" + "\x08" + "VZEROALL\0" +
                    "\x06" + "VMREAD\0" + "\x05" + "EXTRQ\0" + "\x07" + "INSERTQ\0" + "\x07" + "VMWRITE\0" + "\x06" + "HADDPD\0" +
                    "\x06" + "HADDPS\0" + "\x07" + "VHADDPD\0" + "\x07" + "VHADDPS\0" + "\x06" + "HSUBPD\0" + "\x06" + "HSUBPS\0" +
                    "\x07" + "VHSUBPD\0" + "\x07" + "VHSUBPS\0" + "\x06" + "FXSAVE\0" + "\x07" + "FXRSTOR\0" +
                    "\x04" + "XAVE\0" + "\x06" + "LFENCE\0" + "\x06" + "XRSTOR\0" + "\x06" + "MFENCE\0" + "\x06" + "SFENCE\0" +
                    "\x07" + "CLFLUSH\0" + "\x06" + "POPCNT\0" + "\x03" + "BSR\0" + "\x05" + "LZCNT\0" + "\x07" + "CMPEQPS\0" +
                    "\x07" + "CMPLTPS\0" + "\x07" + "CMPLEPS\0" + "\x0a" + "CMPUNORDPS\0" + "\x08" + "CMPNEQPS\0" +
                    "\x08" + "CMPNLTPS\0" + "\x08" + "CMPNLEPS\0" + "\x08" + "CMPORDPS\0" + "\x07" + "CMPEQPD\0" +
                    "\x07" + "CMPLTPD\0" + "\x07" + "CMPLEPD\0" + "\x0a" + "CMPUNORDPD\0" + "\x08" + "CMPNEQPD\0" +
                    "\x08" + "CMPNLTPD\0" + "\x08" + "CMPNLEPD\0" + "\x08" + "CMPORDPD\0" + "\x07" + "CMPEQSS\0" +
                    "\x07" + "CMPLTSS\0" + "\x07" + "CMPLESS\0" + "\x0a" + "CMPUNORDSS\0" + "\x08" + "CMPNEQSS\0" +
                    "\x08" + "CMPNLTSS\0" + "\x08" + "CMPNLESS\0" + "\x08" + "CMPORDSS\0" + "\x07" + "CMPEQSD\0" +
                    "\x07" + "CMPLTSD\0" + "\x07" + "CMPLESD\0" + "\x0a" + "CMPUNORDSD\0" + "\x08" + "CMPNEQSD\0" +
                    "\x08" + "CMPNLTSD\0" + "\x08" + "CMPNLESD\0" + "\x08" + "CMPORDSD\0" + "\x08" + "VCMPEQPS\0" +
                    "\x08" + "VCMPLTPS\0" + "\x08" + "VCMPLEPS\0" + "\x0b" + "VCMPUNORDPS\0" + "\x09" + "VCMPNEQPS\0" +
                    "\x09" + "VCMPNLTPS\0" + "\x09" + "VCMPNLEPS\0" + "\x09" + "VCMPORDPS\0" + "\x08" + "VCMPEQPD\0" +
                    "\x08" + "VCMPLTPD\0" + "\x08" + "VCMPLEPD\0" + "\x0b" + "VCMPUNORDPD\0" + "\x09" + "VCMPNEQPD\0" +
                    "\x09" + "VCMPNLTPD\0" + "\x09" + "VCMPNLEPD\0" + "\x09" + "VCMPORDPD\0" + "\x08" + "VCMPEQSS\0" +
                    "\x08" + "VCMPLTSS\0" + "\x08" + "VCMPLESS\0" + "\x0b" + "VCMPUNORDSS\0" + "\x09" + "VCMPNEQSS\0" +
                    "\x09" + "VCMPNLTSS\0" + "\x09" + "VCMPNLESS\0" + "\x09" + "VCMPORDSS\0" + "\x08" + "VCMPEQSD\0" +
                    "\x08" + "VCMPLTSD\0" + "\x08" + "VCMPLESD\0" + "\x0b" + "VCMPUNORDSD\0" + "\x09" + "VCMPNEQSD\0" +
                    "\x09" + "VCMPNLTSD\0" + "\x09" + "VCMPNLESD\0" + "\x09" + "VCMPORDSD\0" + "\x06" + "PINSRW\0" +
                    "\x07" + "VPINSRW\0" + "\x06" + "PEXTRW\0" + "\x07" + "VPEXTRW\0" + "\x06" + "SHUFPS\0" + "\x06" + "SHUFPD\0" +
                    "\x07" + "VSHUFPS\0" + "\x07" + "VSHUFPD\0" + "\x09" + "CMPXCHG8B\0" + "\x0a" + "CMPXCHG16B\0" +
                    "\x07" + "VMPTRST\0" + "\x08" + "ADDSUBPD\0" + "\x08" + "ADDSUBPS\0" + "\x09" + "VADDSUBPD\0" +
                    "\x09" + "VADDSUBPS\0" + "\x05" + "PSRLW\0" + "\x06" + "VPSRLW\0" + "\x05" + "PSRLD\0" + "\x06" + "VPSRLD\0" +
                    "\x05" + "PSRLQ\0" + "\x06" + "VPSRLQ\0" + "\x05" + "PADDQ\0" + "\x06" + "VPADDQ\0" + "\x06" + "PMULLW\0" +
                    "\x07" + "VPMULLW\0" + "\x07" + "MOVQ2DQ\0" + "\x07" + "MOVDQ2Q\0" + "\x08" + "PMOVMSKB\0" +
                    "\x09" + "VPMOVMSKB\0" + "\x07" + "PSUBUSB\0" + "\x08" + "VPSUBUSB\0" + "\x07" + "PSUBUSW\0" +
                    "\x08" + "VPSUBUSW\0" + "\x06" + "PMINUB\0" + "\x07" + "VPMINUB\0" + "\x04" + "PAND\0" + "\x05" + "VPAND\0" +
                    "\x07" + "PADDUSB\0" + "\x08" + "VPADDUSW\0" + "\x07" + "PADDUSW\0" + "\x06" + "PMAXUB\0" +
                    "\x07" + "VPMAXUB\0" + "\x05" + "PANDN\0" + "\x06" + "VPANDN\0" + "\x05" + "PAVGB\0" + "\x06" + "VPAVGB\0" +
                    "\x05" + "PSRAW\0" + "\x06" + "VPSRAW\0" + "\x05" + "PSRAD\0" + "\x06" + "VPSRAD\0" + "\x05" + "PAVGW\0" +
                    "\x06" + "VPAVGW\0" + "\x07" + "PMULHUW\0" + "\x08" + "VPMULHUW\0" + "\x06" + "PMULHW\0" +
                    "\x07" + "VPMULHW\0" + "\x09" + "CVTTPD2DQ\0" + "\x08" + "CVTDQ2PD\0" + "\x08" + "CVTPD2DQ\0" +
                    "\x0a" + "VCVTTPD2DQ\0" + "\x09" + "VCVTDQ2PD\0" + "\x09" + "VCVTPD2DQ\0" + "\x06" + "MOVNTQ\0" +
                    "\x07" + "MOVNTDQ\0" + "\x08" + "VMOVNTDQ\0" + "\x06" + "PSUBSB\0" + "\x07" + "VPSUBSB\0" +
                    "\x06" + "PSUBSW\0" + "\x07" + "VPSUBSW\0" + "\x06" + "PMINSW\0" + "\x07" + "VPMINSW\0" + "\x03" + "POR\0" +
                    "\x04" + "VPOR\0" + "\x06" + "PADDSB\0" + "\x07" + "VPADDSB\0" + "\x06" + "PADDSW\0" + "\x07" + "VPADDSW\0" +
                    "\x06" + "PMAXSW\0" + "\x07" + "VPMAXSW\0" + "\x04" + "PXOR\0" + "\x05" + "VPXOR\0" + "\x05" + "LDDQU\0" +
                    "\x06" + "VLDDQU\0" + "\x05" + "PSLLW\0" + "\x06" + "VPSLLW\0" + "\x05" + "PSLLD\0" + "\x06" + "VPSLLD\0" +
                    "\x05" + "PSLLQ\0" + "\x06" + "VPSLLQ\0" + "\x07" + "PMULUDQ\0" + "\x08" + "VPMULUDQ\0" + "\x07" + "PMADDWD\0" +
                    "\x08" + "VPMADDWD\0" + "\x06" + "PSADBW\0" + "\x07" + "VPSADBW\0" + "\x08" + "MASKMOVQ\0" +
                    "\x0a" + "MASKMOVDQU\0" + "\x0b" + "VMASKMOVDQU\0" + "\x05" + "PSUBB\0" + "\x06" + "VPSUBB\0" +
                    "\x05" + "PSUBW\0" + "\x06" + "VPSUBW\0" + "\x05" + "PSUBD\0" + "\x06" + "VPSUBD\0" + "\x05" + "PSUBQ\0" +
                    "\x06" + "VPSUBQ\0" + "\x05" + "PADDB\0" + "\x06" + "VPADDB\0" + "\x05" + "PADDW\0" + "\x06" + "VPADDW\0" +
                    "\x05" + "PADDD\0" + "\x06" + "VPADDD\0" + "\x07" + "FNSTENV\0" + "\x06" + "FSTENV\0" + "\x06" + "FNSTCW\0" +
                    "\x05" + "FSTCW\0" + "\x06" + "FNCLEX\0" + "\x05" + "FCLEX\0" + "\x06" + "FNINIT\0" + "\x05" + "FINIT\0" +
                    "\x06" + "FNSAVE\0" + "\x05" + "FSAVE\0" + "\x06" + "FNSTSW\0" + "\x05" + "FSTSW\0" + "\x06" + "PSHUFB\0" +
                    "\x07" + "VPSHUFB\0" + "\x06" + "PHADDW\0" + "\x07" + "VPHADDW\0" + "\x06" + "PHADDD\0" + "\x07" + "VPHADDD\0" +
                    "\x07" + "PHADDSW\0" + "\x08" + "VPHADDSW\0" + "\x09" + "PMADDUBSW\0" + "\x0a" + "VPMADDUBSW\0" +
                    "\x06" + "PHSUBW\0" + "\x07" + "VPHSUBW\0" + "\x06" + "PHSUBD\0" + "\x07" + "VPHSUBD\0" + "\x07" + "PHSUBSW\0" +
                    "\x08" + "VPHSUBSW\0" + "\x06" + "PSIGNB\0" + "\x07" + "VPSIGNB\0" + "\x06" + "PSIGNW\0" +
                    "\x07" + "VPSIGNW\0" + "\x06" + "PSIGND\0" + "\x07" + "VPSIGND\0" + "\x08" + "PMULHRSW\0" +
                    "\x09" + "VPMULHRSW\0" + "\x09" + "VPERMILPS\0" + "\x09" + "VPERMILPD\0" + "\x08" + "VPTESTPS\0" +
                    "\x08" + "VPTESTPD\0" + "\x08" + "PBLENDVB\0" + "\x08" + "BLENDVPS\0" + "\x08" + "BLENDVPD\0" +
                    "\x05" + "PTEST\0" + "\x06" + "VPTEST\0" + "\x0c" + "VBROADCASTSS\0" + "\x0c" + "VBROADCASTSD\0" +
                    "\x0e" + "VBROADCASTF128\0" + "\x05" + "PABSB\0" + "\x06" + "VPABSB\0" + "\x05" + "PABSW\0" +
                    "\x06" + "VPABSW\0" + "\x05" + "PABSD\0" + "\x06" + "VPABSD\0" + "\x08" + "PMOVSXBW\0" + "\x09" + "VPMOVSXBW\0" +
                    "\x08" + "PMOVSXBD\0" + "\x09" + "VPMOVSXBD\0" + "\x08" + "PMOVSXBQ\0" + "\x09" + "VPMOVSXBQ\0" +
                    "\x08" + "PMOVSXWD\0" + "\x09" + "VPMOVSXWD\0" + "\x08" + "PMOVSXWQ\0" + "\x09" + "VPMOVSXWQ\0" +
                    "\x08" + "PMOVSXDQ\0" + "\x09" + "VPMOVSXDQ\0" + "\x06" + "PMULDQ\0" + "\x07" + "VPMULDQ\0" +
                    "\x07" + "PCMPEQQ\0" + "\x08" + "VPCMPEQQ\0" + "\x08" + "MOVNTDQA\0" + "\x09" + "VMOVNTDQA\0" +
                    "\x08" + "PACKUSDW\0" + "\x09" + "VPACKUSDW\0" + "\x0a" + "VMASKMOVPS\0" + "\x0a" + "VMASKMOVPD\0" +
                    "\x08" + "PMOVZXBW\0" + "\x09" + "VPMOVZXBW\0" + "\x08" + "PMOVZXBD\0" + "\x09" + "VPMOVZXBD\0" +
                    "\x08" + "PMOVZXBQ\0" + "\x09" + "VPMOVZXBQ\0" + "\x08" + "PMOVZXWD\0" + "\x09" + "VPMOVZXWD\0" +
                    "\x08" + "PMOVZXWQ\0" + "\x09" + "VPMOVZXWQ\0" + "\x08" + "PMOVZXDQ\0" + "\x09" + "VPMOVZXDQ\0" +
                    "\x07" + "PCMPGTQ\0" + "\x08" + "VPCMPGTQ\0" + "\x06" + "PMINSB\0" + "\x07" + "VPMINSB\0" +
                    "\x06" + "PMINSD\0" + "\x07" + "VPMINSD\0" + "\x06" + "PMINUW\0" + "\x07" + "VPMINUW\0" + "\x06" + "PMINUD\0" +
                    "\x07" + "VPMINUD\0" + "\x06" + "PMAXSB\0" + "\x07" + "VPMAXSB\0" + "\x06" + "PMAXSD\0" + "\x07" + "VPMAXSD\0" +
                    "\x06" + "PMAXUW\0" + "\x07" + "VPMAXUW\0" + "\x06" + "PMAXUD\0" + "\x07" + "VPMAXUD\0" + "\x06" + "PMULLD\0" +
                    "\x07" + "VPMULLD\0" + "\x0a" + "PHMINPOSUW\0" + "\x0b" + "VPHMINPOSUW\0" + "\x06" + "INVEPT\0" +
                    "\x07" + "INVVPID\0" + "\x0e" + "VFMADDSUB132PS\0" + "\x0e" + "VFMADDSUB132PD\0" + "\x0e" + "VFMSUBADD132PS\0" +
                    "\x0e" + "VFMSUBADD132PD\0" + "\x0b" + "VFMADD132PS\0" + "\x0b" + "VFMADD132PD\0" + "\x0b" + "VFMADD132SS\0" +
                    "\x0b" + "VFMADD132SD\0" + "\x0b" + "VFMSUB132PS\0" + "\x0b" + "VFMSUB132PD\0" + "\x0b" + "VFMSUB132SS\0" +
                    "\x0b" + "VFMSUB132SD\0" + "\x0c" + "VFNMADD132PS\0" + "\x0c" + "VFNMADD132PD\0" + "\x0c" + "VFNMADD132SS\0" +
                    "\x0c" + "VFNMADD132SD\0" + "\x0c" + "VFNMSUB132PS\0" + "\x0c" + "VFNMSUB132PD\0" + "\x0c" + "VFNMSUB132SS\0" +
                    "\x0c" + "VFNMSUB132SD\0" + "\x0e" + "VFMADDSUB213PS\0" + "\x0e" + "VFMADDSUB213PD\0" +
                    "\x0e" + "VFMSUBADD213PS\0" + "\x0e" + "VFMSUBADD213PD\0" + "\x0b" + "VFMADD213PS\0" +
                    "\x0b" + "VFMADD213PD\0" + "\x0b" + "VFMADD213SS\0" + "\x0b" + "VFMADD213SD\0" + "\x0b" + "VFMSUB213PS\0" +
                    "\x0b" + "VFMSUB213PD\0" + "\x0b" + "VFMSUB213SS\0" + "\x0b" + "VFMSUB213SD\0" + "\x0c" + "VFNMADD213PS\0" +
                    "\x0c" + "VFNMADD213PD\0" + "\x0c" + "VFNMADD213SS\0" + "\x0c" + "VFNMADD213SD\0" + "\x0c" + "VFNMSUB213PS\0" +
                    "\x0c" + "VFNMSUB213PD\0" + "\x0c" + "VFNMSUB213SS\0" + "\x0c" + "VFNMSUB213SD\0" + "\x0e" + "VFMADDSUB231PS\0" +
                    "\x0e" + "VFMADDSUB231PD\0" + "\x0e" + "VFMSUBADD231PS\0" + "\x0e" + "VFMSUBADD231PD\0" +
                    "\x0b" + "VFMADD231PS\0" + "\x0b" + "VFMADD231PD\0" + "\x0b" + "VFMADD231SS\0" + "\x0b" + "VFMADD231SD\0" +
                    "\x0b" + "VFMSUB231PS\0" + "\x0b" + "VFMSUB231PD\0" + "\x0b" + "VFMSUB231SS\0" + "\x0b" + "VFMSUB231SD\0" +
                    "\x0c" + "VFNMADD231PS\0" + "\x0c" + "VFNMADD231PD\0" + "\x0c" + "VFNMADD231SS\0" + "\x0c" + "VFNMADD231SD\0" +
                    "\x0c" + "VFNMSUB231PS\0" + "\x0c" + "VFNMSUB231PD\0" + "\x0c" + "VFNMSUB231SS\0" + "\x0c" + "VFNMSUB231SD\0" +
                    "\x06" + "AESIMC\0" + "\x07" + "VAESIMC\0" + "\x06" + "AESENC\0" + "\x07" + "VAESENC\0" + "\x0a" + "AESENCLAST\0" +
                    "\x0b" + "VAESENCLAST\0" + "\x06" + "AESDEC\0" + "\x07" + "VAESDEC\0" + "\x0a" + "AESDECLAST\0" +
                    "\x0b" + "VAESDECLAST\0" + "\x05" + "MOVBE\0" + "\x05" + "CRC32\0" + "\x0a" + "VPERM2F128\0" +
                    "\x07" + "ROUNDPS\0" + "\x08" + "VROUNDPS\0" + "\x07" + "ROUNDPD\0" + "\x08" + "VROUNDPD\0" +
                    "\x07" + "ROUNDSS\0" + "\x08" + "VROUNDSS\0" + "\x07" + "ROUNDSD\0" + "\x08" + "VROUNDSD\0" +
                    "\x07" + "BLENDPS\0" + "\x08" + "VBLENDPS\0" + "\x07" + "BLENDPD\0" + "\x08" + "VBLENDPD\0" +
                    "\x07" + "PBLENDW\0" + "\x09" + "VPBLENDVW\0" + "\x07" + "PALIGNR\0" + "\x08" + "VPALIGNR\0" +
                    "\x06" + "PEXTRB\0" + "\x07" + "VPEXTRB\0" + "\x06" + "PEXTRD\0" + "\x06" + "PEXTRQ\0" + "\x07" + "VPEXTRD\0" +
                    "\x09" + "EXTRACTPS\0" + "\x0a" + "VEXTRACTPS\0" + "\x0b" + "VINSERTF128\0" + "\x0c" + "VEXTRACTF128\0" +
                    "\x06" + "PINSRB\0" + "\x07" + "VPINSRB\0" + "\x08" + "INSERTPS\0" + "\x09" + "VINSERTPS\0" +
                    "\x06" + "PINSRD\0" + "\x06" + "PINSRQ\0" + "\x07" + "VPINSRD\0" + "\x07" + "VPINSRQ\0" + "\x04" + "DPPS\0" +
                    "\x05" + "VDPPS\0" + "\x04" + "DPPD\0" + "\x05" + "VDPPD\0" + "\x07" + "MPSADBW\0" + "\x08" + "VMPSADBW\0" +
                    "\x09" + "PCLMULQDQ\0" + "\x0a" + "VPCLMULQDQ\0" + "\x09" + "VBLENDVPS\0" + "\x09" + "VBLENDVPD\0" +
                    "\x09" + "VPBLENDVB\0" + "\x09" + "PCMPESTRM\0" + "\x0a" + "VPCMPESTRM\0" + "\x09" + "PCMPESTRI\0" +
                    "\x09" + "VCMPESTRI\0" + "\x09" + "PCMPISTRM\0" + "\x0a" + "VPCMPISTRM\0" + "\x09" + "PCMPISTRI\0" +
                    "\x0a" + "VPCMPISTRI\0" + "\x0f" + "AESKEYGENASSIST\0" + "\x10" + "VAESKEYGENASSIST\0" +
                    "\x06" + "PSRLDQ\0" + "\x07" + "VPSRLDQ\0" + "\x06" + "PSLLDQ\0" + "\x07" + "VPSLLDQ\0" + "\x07" + "LDMXCSR\0" +
                    "\x08" + "VLDMXCSR\0" + "\x07" + "STMXCSR\0" + "\x08" + "VSTMXCSR\0" + "\x07" + "VMPTRLD\0" +
                    "\x07" + "VMCLEAR\0" + "\x05" + "VMXON\0" + "\x04" + "WAIT\0" + "\x06" + "MOVSXD\0" + "\x05" + "PAUSE\0").ToCharArray();
            }
        }

        /// <summary>
        /// Gets the set of register types.
        /// </summary>
        public static WRegister[] REGISTERS
        {
            get
            {
                return new WRegister[]
                {
                    new WRegister(3, "RAX"), new WRegister(3, "RCX"), new WRegister(3, "RDX"), new WRegister(3, "RBX"), new WRegister(3, "RSP"), new WRegister(3, "RBP"), new WRegister(3, "RSI"), new WRegister(3, "RDI"), new WRegister(2, "R8"), new WRegister(2, "R9"), new WRegister(3, "R10"), new WRegister(3, "R11"), new WRegister(3, "R12"), new WRegister(3, "R13"), new WRegister(3, "R14"), new WRegister(3, "R15"),
                    new WRegister(3, "EAX"), new WRegister(3, "ECX"), new WRegister(3, "EDX"), new WRegister(3, "EBX"), new WRegister(3, "ESP"), new WRegister(3, "EBP"), new WRegister(3, "ESI"), new WRegister(3, "EDI"), new WRegister(3, "R8D"), new WRegister(3, "R9D"), new WRegister(4, "R10D"), new WRegister(4, "R11D"), new WRegister(4, "R12D"), new WRegister(4, "R13D"), new WRegister(4, "R14D"), new WRegister(4, "R15D"),
                    new WRegister(2, "AX"), new WRegister(2, "CX"), new WRegister(2, "DX"), new WRegister(2, "BX"), new WRegister(2, "SP"), new WRegister(2, "BP"), new WRegister(2, "SI"), new WRegister(2, "DI"), new WRegister(3, "R8W"), new WRegister(3, "R9W"), new WRegister(4, "R10W"), new WRegister(4, "R11W"), new WRegister(4, "R12W"), new WRegister(4, "R13W"), new WRegister(4, "R14W"), new WRegister(4, "R15W"),
                    new WRegister(2, "AL"), new WRegister(2, "CL"), new WRegister(2, "DL"), new WRegister(2, "BL"), new WRegister(2, "AH"), new WRegister(2, "CH"), new WRegister(2, "DH"), new WRegister(2, "BH"), new WRegister(3, "R8B"), new WRegister(3, "R9B"), new WRegister(4, "R10B"), new WRegister(4, "R11B"), new WRegister(4, "R12B"), new WRegister(4, "R13B"), new WRegister(4, "R14B"), new WRegister(4, "R15B"),
                    new WRegister(3, "SPL"), new WRegister(3, "BPL"), new WRegister(3, "SIL"), new WRegister(3, "DIL"),
                    new WRegister(2, "ES"), new WRegister(2, "CS"), new WRegister(2, "SS"), new WRegister(2, "DS"), new WRegister(2, "FS"), new WRegister(2, "GS"),
                    new WRegister(3, "RIP"),
                    new WRegister(3, "ST0"), new WRegister(3, "ST1"), new WRegister(3, "ST2"), new WRegister(3, "ST3"), new WRegister(3, "ST4"), new WRegister(3, "ST5"), new WRegister(3, "ST6"), new WRegister(3, "ST7"),
                    new WRegister(3, "MM0"), new WRegister(3, "MM1"), new WRegister(3, "MM2"), new WRegister(3, "MM3"), new WRegister(3, "MM4"), new WRegister(3, "MM5"), new WRegister(3, "MM6"), new WRegister(3, "MM7"),
                    new WRegister(4, "XMM0"), new WRegister(4, "XMM1"), new WRegister(4, "XMM2"), new WRegister(4, "XMM3"), new WRegister(4, "XMM4"), new WRegister(4, "XMM5"), new WRegister(4, "XMM6"), new WRegister(4, "XMM7"), new WRegister(4, "XMM8"), new WRegister(4, "XMM9"), new WRegister(5, "XMM10"), new WRegister(5, "XMM11"), new WRegister(5, "XMM12"), new WRegister(5, "XMM13"), new WRegister(5, "XMM14"), new WRegister(5, "XMM15"),
                    new WRegister(4, "YMM0"), new WRegister(4, "YMM1"), new WRegister(4, "YMM2"), new WRegister(4, "YMM3"), new WRegister(4, "YMM4"), new WRegister(4, "YMM5"), new WRegister(4, "YMM6"), new WRegister(4, "YMM7"), new WRegister(4, "YMM8"), new WRegister(4, "YMM9"), new WRegister(5, "YMM10"), new WRegister(5, "YMM11"), new WRegister(5, "YMM12"), new WRegister(5, "YMM13"), new WRegister(5, "YMM14"), new WRegister(5, "YMM15"),
                    new WRegister(3, "CR0"), new WRegister(0, string.Empty), new WRegister(3, "CR2"), new WRegister(3, "CR3"), new WRegister(3, "CR4"), new WRegister(0, string.Empty), new WRegister(0, string.Empty), new WRegister(0, string.Empty), new WRegister(3, "CR8"),
                    new WRegister(3, "DR0"), new WRegister(3, "DR1"), new WRegister(3, "DR2"), new WRegister(3, "DR3"), new WRegister(0, string.Empty), new WRegister(0, string.Empty), new WRegister(3, "DR6"), new WRegister(3, "DR7")
                };
            }
        }

        #endregion

        #endregion

        #region Methods

        /// <summary>
        /// A wrapper for distorm_decompose(), which only takes in the code to be decomposed.
        /// </summary>
        /// <param name="code">The code to be decomposed.</param>
        /// <param name="logFilename">
        /// The name of the file to use to log important updates about the decomposition process.
        /// </param>
        /// <returns>Returns the code to be decomposed on success or an empty array upon failure.</returns>
        /// <remarks>
        /// Usage of brainpower is required to recognize that decomposing a code array of size 0 will also result in
        /// an empty array.
        /// </remarks>
        public static DInst[] Decompose(byte[] code, string logFilename = "Distorm3cs.log")
        {
            GCHandle gch = GCHandle.Alloc(code, GCHandleType.Pinned);

            DistormSimple.CodeInfo ci = new DistormSimple.CodeInfo();
            ci.codeLen = code.Length;
            ci.code = gch.AddrOfPinnedObject();
            ci.codeOffset = 0;
            ci.dt = DistormSimple.DecodeType.Decode32Bits;
            ci.features = DistormSimple.DecomposeFeatures.NONE;

            // Most likely a gross over-estimation of how large to make the array, but it should never fail.
            DistormSimple.DInst[] result = new DistormSimple.DInst[code.Length];
            uint usedInstructionsCount = 0;

            // Decompose the data.
            DistormSimple.DecodeResult r =
                DistormSimple.distorm_decompose(ref ci, result, (uint)result.Length, ref usedInstructionsCount);

            // Release the handle pinned to the code.
            gch.Free();

            // Return false if an error occured during decomposition.
            if (!r.Equals(DistormSimple.DecodeResult.SUCCESS))
            {
                Logger.Log(
                    "Error decomposing data. Result was: " + r.ToString(),
                    logFilename,
                    Logger.Type.CONSOLE | Logger.Type.FILE);
                return new DistormSimple.DInst[0];
            }

            // Resize the array to match the actual number of instructions decoded.
            Array.Resize(ref result, (int)usedInstructionsCount);

            // Return the result.
            return result;
        }

        /// <summary>
        /// Translates opcodes into a list of strings, which each represent an instruction.
        /// </summary>
        /// <param name="code">The code to be disassembled.</param>
        /// <returns>Returns the disassembled instructions.</returns>
        public static List<string> Disassemble(byte[] code)
        {
            List<string> instructions = new List<string>();

            GCHandle gch = GCHandle.Alloc(code, GCHandleType.Pinned);

            // Prepare the _CodeInfo structure for decomposition.
            Distorm._CodeInfo ci = new Distorm._CodeInfo();
            ci.codeLen = code.Length;
            ci.code = gch.AddrOfPinnedObject();
            ci.codeOffset = 0;
            ci.dt = Distorm._DecodeType.Decode32Bits;
            ci.features = Distorm.DF_NONE;

            // Prepare the result instruction buffer to receive the decomposition.
            Distorm._DInst[] result = new Distorm._DInst[code.Length];
            uint usedInstructionsCount = 0;

            // Perform the decomposition.
            Distorm._DecodeResult r =
                Distorm.distorm_decompose(ref ci, result, (uint)result.Length, ref usedInstructionsCount);

            // Release the handle pinned to the code.
            gch.Free();

            // Return an empty list if an error occured during decomposition.
            if (!r.Equals(Distorm._DecodeResult.DECRES_SUCCESS))
            {
                return new List<string>();
            }

            // Prepare a _DecodedInst structure for formatting the results.
            Distorm._DecodedInst inst = new Distorm._DecodedInst();

            for (uint i = 0; i < usedInstructionsCount; ++i)
            {
                // Format the results of the decomposition.
                Distorm.distorm_format(ref ci, ref result[i], ref inst);

                // Add it to the buffer to be verified.
                if (string.IsNullOrEmpty(inst.Operands))
                {
                    instructions.Add(inst.Mnemonic);
                }
                else
                {
                    instructions.Add(inst.Mnemonic + " " + inst.Operands);
                }
            }

            return instructions;
        }

        /// <summary>
        /// Get the Instruction-Set-Class type of the instruction.
        /// </summary>
        /// <param name="meta">The meta value from a DInst structure.</param>
        /// <returns>
        /// Returns the Instruction-Set-Class type of the instruction.
        /// I.E: INTEGER, FPU, and many more.
        /// </returns>
        /// <remarks>This is the META_GET_ISC macro in distorm.h.</remarks>
        public static InstructionSetClass MetaGetISC(byte meta)
        {
            return (InstructionSetClass)((meta >> 3) & 0x1f);
        }

        /// <summary>
        /// Set the Instruction-Set-Class type of the instruction.
        /// </summary>
        /// <param name="di">The instruction that will have its meta value set.</param>
        /// <param name="isc">The Instruction-Set-Class type to set to the meta value.</param>
        public static void MetaSetISC(DInst di, InstructionSetClass isc)
        {
            di.meta |= (byte)((short)isc << 3);
        }

        /// <summary>
        /// Get the flow control flags of the instruction.
        /// </summary>
        /// <param name="meta">The meta flag of a Dinst structure.</param>
        /// <returns>Returns the control flow flag value.</returns>
        public static FlowControl MetaGetFC(byte meta)
        {
            return (FlowControl)(meta & 0x7);
        }

        /// <summary>
        /// Get the target address of a branching instruction.
        /// </summary>
        /// <param name="di">A decomposed instruction, specifically some type of a branch instruction.</param>
        /// <returns>Returns the target address of the branch.</returns>
        /// <remarks>This is the INSTRUCTION_GET_TARGET macro in distorm.h</remarks>
        public static ulong InstructionGetTarget(DInst di)
        {
            return di.addr + di.imm.addr + di.size;
        }

        /// <summary>
        /// Get the target address of a RIP-relative memory indirection.
        /// </summary>
        /// <param name="di">A decomposed instruction.</param>
        /// <returns>Returns the target address of a RIP-relative memory indirection.</returns>
        /// <remarks>This is the INSTRUCTION_GET_RIP_TARGET macro in distorm.h.</remarks>
        public static ulong InstructionGetRipTarget(DInst di)
        {
            return di.addr + di.disp + di.size;
        }

        /// <summary>
        /// Sets the operand size in the flags value of an instruction.
        /// </summary>
        /// <param name="di">The instruction that will have its flags value modified.</param>
        /// <param name="size">The new size of the operand.</param>
        /// <remarks>This is the FLAG_SET_OPSIZE macro in distorm.h.</remarks>
        public static void FlagSetOpSize(DInst di, byte size)
        {
            di.flags |= (ushort)((size & 3) << 8);
        }

        /// <summary>
        /// Sets the address size in the flags value of an instruction.
        /// </summary>
        /// <param name="di">The instruction that will have its flags value modified.</param>
        /// <param name="size">The new size of the address.</param>
        /// <remarks>This is the FLAG_SET_ADDRSIZE macro in distorm.h.</remarks>
        public static void FlagSetAddrSize(DInst di, byte size)
        {
            di.flags |= (ushort)((size & 3) << 10);
        }

        /// <summary>
        /// Gets the operand size from the provided flags value.
        /// </summary>
        /// <param name="flags">The flags value that holds the operand size.</param>
        /// <returns>Returns the operand size: 0 - 16 bits / 1 - 32 bits / 2 - 64 bits / 3 reserved</returns>
        /// <remarks>This is the FLAG_GET_OPSIZE macro in distorm.h.</remarks>
        public static byte FlagGetOpSize(ushort flags)
        {
            return (byte)((flags >> 8) & 3);
        }

        /// <summary>
        /// Gets the address size from the provided flags value.
        /// </summary>
        /// <param name="flags">The flags value that holds the address size.</param>
        /// <returns>Returns the address size: 0 - 16 bits / 1 - 32 bits / 2 - 64 bits / 3 reserved</returns>
        /// <remarks>This is the FLAG_GET_ADDRSIZE macro in distorm.h.</remarks>
        public static byte FlagGetAddrSize(ushort flags)
        {
            return (byte)((flags >> 10) & 3);
        }

        /// <summary>
        /// Retrieves the prefix of an instruction, based on the provide flags value.
        /// </summary>
        /// <param name="flags">The flags value that holds the prefix of an instruction.</param>
        /// <returns>Returns the prefix of an instruction (FLAG_LOCK, FLAG_REPNZ, FLAG_REP).</returns>
        /// <remarks>This is the FLAG_GET_PREFIX macro in distorm.h.</remarks>
        public static byte FlagGetPrefix(ushort flags)
        {
            return (byte)(flags & 7);
        }

        /// <summary>
        /// Sets the segment value of an instruction.
        /// </summary>
        /// <param name="di">The instruction that will have its segment value set.</param>
        /// <param name="segment">The value to set which the instruction's segment value will be set.</param>
        /// <remarks>This is the SEGMENT_SET macro in distorm.h.</remarks>
        public static void SegmentSet(DInst di, byte segment)
        {
            di.segment |= segment;
        }

        /// <summary>
        /// Gets the segment register index from a segment value.
        /// </summary>
        /// <param name="segment">A segment value, taken from a decomposed Dinst structure.</param>
        /// <returns>Returns segment register index.</returns>
        /// <remarks>This is the SEGMENT_GET macro in distorm.h.</remarks>
        public static byte SegmentGet(byte segment)
        {
            return segment == R_NONE ? R_NONE : (byte)(segment & 0x7f);
        }

        /// <summary>
        /// Determines if the segment value is set to the default segment value.
        /// </summary>
        /// <param name="segment">The segment value to test.</param>
        /// <returns>
        /// Returns true if the segment register is the default one for the operand. For instance:
        /// MOV [EBP], AL - the default segment register is SS. However,
        /// MOV [FS:EAX], AL - The default segment is DS, but we overrode it with FS,
        /// therefore the function will return FALSE.
        /// </returns>
        /// <remarks>This is the SEGMENT_IS_DEFAULT macro in distorm.h.</remarks>
        public static bool SegmentIsDefault(byte segment)
        {
            return (segment & SEGMENT_DEFAULT) == SEGMENT_DEFAULT;
        }

        /// <summary>
        /// Decomposes data into assembly format, using the native distorm_decompose function.
        /// </summary>
        /// <param name="ci">
        /// The CodeInfo structure that holds the data that will be decomposed.
        /// </param>
        /// <param name="result">
        /// Array of type Dinst which will be used by this function in order to return the disassembled instructions.
        /// </param>
        /// <param name="maxInstructions">
        /// The maximum number of entries in the result array that you pass to this function, so it won't exceed its
        /// bound.
        /// </param>
        /// <param name="usedInstructionsCount">
        /// Number of the instruction that successfully were disassembled and written to the result array. Will hold
        /// the number of entries used in the result array and the result array itself will be filled with the
        /// disassembled instructions.
        /// </param>
        /// <returns>
        /// DECRES_SUCCESS on success (no more to disassemble), INPUTERR on input error (null code buffer, invalid
        /// decoding mode, etc...), MEMORYERR when there are not enough entries to use in the result array, BUT YOU
        /// STILL have to check for usedInstructionsCount!
        /// </returns>
        /// <remarks>
        /// Side-Effects: Even if the return code is MEMORYERR, there might STILL be data in the array you passed,
        ///               this function will try to use as much entries as possible!
        /// Notes: 1) The minimal size of maxInstructions is 15.
        ///        2) You will have to synchronize the offset,code and length by yourself if you pass code fragments
        ///           and not a complete code block!
        /// </remarks>
        [DllImport("distorm3.dll", CharSet = CharSet.Ansi, CallingConvention = CallingConvention.Cdecl,
            EntryPoint = "distorm_decompose" + ArchitectureString)]
        public static extern DecodeResult distorm_decompose(
            ref CodeInfo ci, [In, Out] DInst[] result, uint maxInstructions, ref uint usedInstructionsCount);

        /// <summary>
        /// Convert a Dinst structure, which was produced from the distorm_decompose function, into text.
        /// </summary>
        /// <param name="ci">The CodeInfo structure that holds the data that was decomposed.</param>
        /// <param name="di">The decoded instruction.</param>
        /// <param name="result">The variable to which the formatted instruction will be returned.</param>
        [DllImport("distorm3.dll", CharSet = CharSet.Ansi, CallingConvention = CallingConvention.Cdecl,
            EntryPoint = "distorm_format" + ArchitectureString)]
        public static extern void distorm_format(ref CodeInfo ci, ref DInst di, ref DecodedInst result);

        /// <summary>
        /// Gets the string for a given register index.
        /// </summary>
        /// <param name="r">
        /// The value of the index of an Operand structure, within the Dinst structure, if that operand represents a
        /// register.
        /// </param>
        /// <returns>Returns the string for a given register index.</returns>
        /// <remarks>This is the GET_REGISTER_NAME macro in mnemonics.h.</remarks>
        public static WRegister GetRegisterName(uint r)
        {
            return DistormSimple.REGISTERS[r];
        }

        /// <summary>
        /// Get the textual representation for an instruction.
        /// </summary>
        /// <param name="m">The opcode value of a Dinst structure.</param>
        /// <returns>Returns the textual representation for an instruction.</returns>
        /// <remarks>This is the GET_MNEMONIC_NAME macro in mnemonics.h.</remarks>
        public static WMnemonic GetMnemonicName(uint m)
        {
            WMnemonic wm = new WMnemonic();
            wm.length = MNEMONICS[m];
            wm.p = new char[wm.length];
            for (uint i = 0; i < wm.length; ++i)
            {
                wm.p[i] = DistormSimple.MNEMONICS[m + 1 + i];
            }

            return wm;
        }

        #endregion

        #region Structures

        /// <summary>
        /// A string representation used when returning a decoded instruction.
        /// </summary>
        [StructLayout(LayoutKind.Sequential)]
        public struct WString
        {
            /// <summary>
            /// The length of p.
            /// </summary>
            public uint length;

            /// <summary>
            /// A null terminated string.
            /// </summary>
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = MAX_TEXT_SIZE)]
            public byte[] p;
        }

        /// <summary>
        /// Old decoded instruction structure in text format.
        /// Used only for backward compatibility with diStorm64.
        /// This structure holds all information the disassembler generates per instruction.
        /// </summary>
        [StructLayout(LayoutKind.Sequential)]
        public struct DecodedInst
        {
            /// <summary>
            /// Mnemonic of decoded instruction, prefixed if required by REP, LOCK etc.
            /// </summary>
            private WString mnemonic;

            /// <summary>
            /// Operands of the decoded instruction, up to 3 operands, comma-seperated.
            /// </summary>
            private WString operands;

            /// <summary>
            /// Hex dump - little endian, including prefixes.
            /// </summary>
            private WString instructionHex;

            /// <summary>
            /// Size of decoded instruction.
            /// </summary>
            public uint size;

            /// <summary>
            /// Start offset of the decoded instruction.
            /// </summary>
            public ulong offset;

            /// <summary>
            /// Gets the mnemonic as a C# string.
            /// </summary>
            public string Mnemonic
            {
                get
                {
                    string longMnemonic = Encoding.UTF8.GetString(this.mnemonic.p);
                    return longMnemonic.Substring(0, (int)this.mnemonic.length).ToLower();
                }
            }

            /// <summary>
            /// Gets the operands as a C# string.
            /// </summary>
            public string Operands
            {
                get
                {
                    string longOperands = Encoding.UTF8.GetString(this.operands.p);
                    return longOperands.Substring(0, (int)this.operands.length);
                }
            }

            /// <summary>
            /// Gets the instruction hex as a C# string.
            /// </summary>
            public string InstructionHex
            {
                get
                {
                    string longInstructionHex = Encoding.UTF8.GetString(this.instructionHex.p);
                    return longInstructionHex.Substring(0, (int)this.instructionHex.length);
                }
            }

            /// <summary>
            /// Returns this instruction in a simple format.
            /// </summary>
            /// <returns>Returns this instruction in the following format: "address: mnemonic operands"</returns>
            public override string ToString()
            {
                return this.offset.ToString("X").PadLeft(8, '0') + ": " + this.Mnemonic +
                       (this.Operands.Length > 0 ? " " + this.Operands : string.Empty);
            }
        }

        /// <summary>
        /// Represents an operand in an ASM instruction.
        /// </summary>
        [StructLayout(LayoutKind.Sequential)]
        public struct Operand
        {
            /// <summary>
            /// Type of operand:
            /// NONE: operand is to be ignored.
            /// REG: index holds global register index.
            /// IMM: instruction.imm.
            /// IMM1: instruction.imm.ex.i1.
            /// IMM2: instruction.imm.ex.i2.
            /// DISP: memory dereference with displacement only, instruction.disp.
            /// SMEM: simple memory dereference with optional displacement (a single register memory dereference).
            /// MEM: complex memory dereference (optional fields: s/i/b/disp).
            /// PC: the relative address of a branch instruction (instruction.imm.addr).
            /// PTR: the absolute target address of a far branch instruction (instruction.imm.ptr.seg/off).
            /// </summary>
            public OperandType type;

            /// <summary>
            /// Index of:
            /// REG: holds global register index
            /// SMEM: holds the 'base' register. E.G: [ECX], [EBX+0x1234] are both in operand.index.
            /// MEM: holds the 'index' register. E.G: [EAX*4] is in operand.index.
            /// </summary>
            public byte index;

            /// <summary>
            /// Size of:
            /// REG: register
            /// IMM: instruction.imm
            /// IMM1: instruction.imm.ex.i1
            /// IMM2: instruction.imm.ex.i2
            /// DISP: instruction.disp
            /// SMEM: size of indirection.
            /// MEM: size of indirection.
            /// PC: size of the relative offset
            /// PTR: size of instruction.imm.ptr.off (16 or 32)
            /// </summary>
            public ushort size;

            /// <summary>
            /// Gets the name of the register associated with this operand in lowercase.
            /// </summary>
            public string RegisterName
            {
                get
                {
                    if (this.type == OperandType.REG || this.type == OperandType.SMEM)
                    {
                        return new string(DistormSimple.REGISTERS[this.index].p).ToLower();
                    }
                    else
                    {
                        return string.Empty;
                    }
                }
            }
        }

        /// <summary>
        /// Used by PTR.
        /// </summary>
        [StructLayout(LayoutKind.Sequential)]
        public struct _Value_ptr
        {
            /// <summary>
            /// The segment in which the value resides.
            /// </summary>
            public ushort seg;

            /// <summary>
            /// The offset from the segment in which the value resides. Can be 16 or 32 bits, size is in ops[n].size.
            /// </summary>
            public uint off;
        }

        /// <summary>
        /// Used by IMM1 (i1) and IMM2 (i2). ENTER instruction only.
        /// </summary>
        [StructLayout(LayoutKind.Sequential)]
        public struct _Value_ex
        {
            /// <summary>
            /// The first immediate value.
            /// </summary>
            public uint i1;

            /// <summary>
            /// The second immediate value.
            /// </summary>
            public uint i2;
        }

        /// <summary>
        /// Represents a value within an instruction.
        /// </summary>
        [StructLayout(LayoutKind.Explicit)]
        public struct _Value
        {
            /// <summary>
            /// The value, as a signed 1-byte number.
            /// </summary>
            [FieldOffset(0)]
            public sbyte sbyte_;

            /// <summary>
            /// The value, as an unsigned 1-byte number.
            /// </summary>
            [FieldOffset(0)]
            public byte byte_;

            /// <summary>
            /// The value, as a signed 2-byte number.
            /// </summary>
            [FieldOffset(0)]
            public short sword;

            /// <summary>
            /// The value, as an unsigned 2-byte number.
            /// </summary>
            [FieldOffset(0)]
            public ushort word;

            /// <summary>
            /// The value, as a signed 4-byte number.
            /// </summary>
            [FieldOffset(0)]
            public int sdword;

            /// <summary>
            /// The value, as an unsigned 4-byte number.
            /// </summary>
            [FieldOffset(0)]
            public uint dword;

            /// <summary>
            /// The value, as a signed 8-byte number. All immediates are SIGN-EXTENDED to 64 bits!
            /// </summary>
            [FieldOffset(0)]
            public long sqword;

            /// <summary>
            /// The value, as an unsigned 8-byte number.
            /// </summary>
            [FieldOffset(0)]
            public ulong qword;

            /// <summary>
            /// The value, as an address. Used by PC: (Use GET_TARGET_ADDR).
            /// </summary>
            [FieldOffset(0)]
            public ulong addr;

            /// <summary>
            /// The value, as a pointer. Used by PTR.
            /// </summary>
            [FieldOffset(0)]
            public _Value_ptr ptr;

            /// <summary>
            /// Used by IMM1 (i1) and IMM2 (i2). ENTER instruction only.
            /// </summary>
            [FieldOffset(0)]
            public _Value_ex ex;
        }

        /// <summary>
        /// Represents the new decoded instruction, used by the decompose interface.
        /// </summary>
        [StructLayout(LayoutKind.Sequential)]
        public struct DInst
        {
            /// <summary>
            /// The immediate value of the instruction.
            /// Used by ops[n].type == IMM/IMM1&IMM2/PTR/PC. Its size is ops[n].size.
            /// </summary>
            public _Value imm;

            /// <summary>
            /// Used by ops[n].type == SMEM/MEM/DISP. Its size is dispSize.
            /// </summary>
            public ulong disp;

            /// <summary>
            /// Virtual address of first byte of instruction.
            /// </summary>
            public ulong addr;

            /// <summary>
            /// General flags of instruction, holds prefixes and more, if FLAG_NOT_DECODABLE, instruction is invalid.
            /// </summary>
            public ushort flags;

            /// <summary>
            /// Unused prefixes mask, for each bit that is set that prefix is not used (LSB is byte [addr + 0]).
            /// </summary>
            public ushort unusedPrefixesMask;

            /// <summary>
            /// Mask of registers that were used in the operands, only used for quick look up, in order to know *some*
            /// operand uses that register class.
            /// </summary>
            public ushort usedRegistersMask;

            /// <summary>
            /// ID of opcode in the global opcode table. Use for mnemonic look up.
            /// </summary>
            public ushort opcode;

            /// <summary>
            /// Up to four operands per instruction, ignored if ops[n].type == NONE.
            /// </summary>
            [MarshalAs(UnmanagedType.ByValArray, ArraySubType = UnmanagedType.I4, SizeConst = OPERANDS_NO)]
            public Operand[] ops;

            /// <summary>
            /// Size of the whole instruction.
            /// </summary>
            public byte size;

            /// <summary>
            /// Segment information of memory indirection, default segment, or overriden one, can be -1. Use SEGMENT
            /// macros.
            /// </summary>
            public byte segment;

            /// <summary>
            /// Used by ops[n].type == MEM. Base global register index (might be R_NONE), scale size (2/4/8), ignored
            /// for 0 or 1.
            /// </summary>
            public byte base_, scale;

            /// <summary>
            /// The size of the 'disp' field in bytes.
            /// </summary>
            public byte dispSize;

            /// <summary>
            /// Meta defines the instruction set class, and the flow control flags. Use META macros.
            /// </summary>
            public byte meta;

            /// <summary>
            /// Gets the instruction type, using this instruction's opcode value.
            /// </summary>
            public InstructionType InstructionType
            {
                get
                {
                    return (InstructionType)this.opcode;
                }
            }
        }

        /// <summary>
        /// Holds various pieces of information that are required by the distorm_decompose function.
        /// </summary>
        [StructLayout(LayoutKind.Sequential)]
        public struct CodeInfo
        {
            /// <summary>
            /// The offset of the code.
            /// </summary>
            public ulong codeOffset;

            /// <summary>
            /// The next offset to be analyzed. nextOffset is OUT only.
            /// </summary>
            public ulong nextOffset;

            /// <summary>
            /// A pointer to unmanaged code that will be decomposed/disassembled.
            /// </summary>
            public IntPtr code;

            /// <summary>
            /// The length of the code that will be decomposed/disassembled.
            /// </summary>
            public int codeLen;

            /// <summary>
            /// The way this code should be decomposed/disassembled.
            /// </summary>
            public DecodeType dt;

            /// <summary>
            /// Features that should be enabled during decomposition.
            /// </summary>
            public DecomposeFeatures features;
        }

        /// <summary>
        /// A mneumonic string representation.
        /// </summary>
        public struct WMnemonic
        {
            /// <summary>
            /// The length of the mneumonic string.
            /// </summary>
            public char length;

            /// <summary>
            /// A null terminated string, which contains 'length' characters.
            /// </summary>
            public char[] p; // len = 1
        }

        /// <summary>
        /// A register string representation.
        /// </summary>
        public struct WRegister
        {
            /// <summary>
            /// The length of the register string.
            /// </summary>
            public uint length;

            /// <summary>
            /// A null terminated string.
            /// </summary>
            public char[] p; // len = 6

            /// <summary>
            /// Initializes a new instance of the WRegister struct.
            /// </summary>
            /// <param name="length">The length of the register string to be created.</param>
            /// <param name="p">The array of characters that holds the register name.</param>
            public WRegister(uint length, string p)
            {
                this.length = length;
                this.p = p.ToCharArray();
            }
        }

        #endregion
    }
}
