//-----------------------------------------------------------------------
// <copyright file="Distorm.cs">
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>
// </copyright>
//-----------------------------------------------------------------------

namespace distorm3cs
{
    using System;
    using System.Runtime.InteropServices;
    using System.Text;

    /// <summary>
    /// The primary interface for calling distorm3 functions.
    /// </summary>
    public class Distorm
    {
        #region Constants

        #region Flags For Comparison Against _DInst.flags

        /// <summary>
        /// No opcode ID is available.
        /// </summary>
        public const ushort OPCODE_ID_NONE = 0;

        /// <summary>
        /// Instruction could not be disassembled.
        /// </summary>
        public const ushort FLAG_NOT_DECODABLE = unchecked((ushort)-1);

        /// <summary>
        /// The instruction locks memory access.
        /// </summary>
        public const ushort FLAG_LOCK = (1 << 0);

        /// <summary>
        /// The instruction is prefixed with a REPNZ.
        /// </summary>
        public const ushort FLAG_REPNZ = (1 << 1);

        /// <summary>
        /// The instruction is prefixed with a REP, this can be a REPZ, it depends on the specific instruction.
        /// </summary>
        public const ushort FLAG_REP = (1 << 2);

        /// <summary>
        /// Indicates there is a hint taken for Jcc instructions only.
        /// </summary>
        public const ushort FLAG_HINT_TAKEN = (1 << 3);

        /// <summary>
        /// Indicates there is a hint non-taken for Jcc instructions only.
        /// </summary>
        public const ushort FLAG_HINT_NOT_TAKEN = (1 << 4);

        /// <summary>
        /// The Imm value is signed extended.
        /// </summary>
        public const ushort FLAG_IMM_SIGNED = (1 << 5);

        /// <summary>
        /// The destination operand is writable.
        /// </summary>
        public const ushort FLAG_DST_WR = (1 << 6);

        /// <summary>
        /// The instruction uses RIP-relative indirection.
        /// </summary>
        public const ushort FLAG_RIP_RELATIVE = (1 << 7);

        #endregion

        #region Register masks for quick look up

        // Each mask indicates one of a register-class that is being used in some operand.

        /// <summary>
        /// AL, AH, AX, EAX, RAX
        /// </summary>
        public const uint RM_AX = 1;

        /// <summary>
        /// CL, CH, CX, ECX, RCX
        /// </summary>
        public const uint RM_CX = 2;

        /// <summary>
        /// DL, DH, DX, EDX, RDX
        /// </summary>
        public const uint RM_DX = 4;

        /// <summary>
        /// BL, BH, BX, EBX, RBX
        /// </summary>
        public const uint RM_BX = 8;

        /// <summary>
        /// SPL, SP, ESP, RSP
        /// </summary>
        public const uint RM_SP = 0x10;

        /// <summary>
        /// BPL, BP, EBP, RBP
        /// </summary>
        public const uint RM_BP = 0x20;

        /// <summary>
        /// SIL, SI, ESI, RSI
        /// </summary>
        public const uint RM_SI = 0x40;

        /// <summary>
        /// DIL, DI, EDI, RDI
        /// </summary>
        public const uint RM_DI = 0x80;

        /// <summary>
        /// ST(0) - ST(7)
        /// </summary>
        public const uint RM_FPU = 0x100;

        /// <summary>
        /// MM0 - MM7
        /// </summary>
        public const uint RM_MMX = 0x200;

        /// <summary>
        /// XMM0 - XMM15
        /// </summary>
        public const uint RM_SSE = 0x400;

        /// <summary>
        /// YMM0 - YMM15
        /// </summary>
        public const uint RM_AVX = 0x800;

        /// <summary>
        /// CR0, CR2, CR3, CR4, CR8
        /// </summary>
        public const uint RM_CR = 0x1000;

        /// <summary>
        /// DR0, DR1, DR2, DR3, DR6, DR7
        /// </summary>
        public const uint RM_DR = 0x2000;

        #endregion

        #region Features for decompose

        /// <summary>
        /// No features should be used during decomposition.
        /// </summary>
        public const uint DF_NONE = 0;

        /// <summary>
        /// The decoder will limit addresses to a maximum of 16 bits.
        /// </summary>
        public const uint DF_MAXIMUM_ADDR16 = 1;

        /// <summary>
        /// The decoder will limit addresses to a maximum of 32 bits.
        /// </summary>
        public const uint DF_MAXIMUM_ADDR32 = 2;

        /// <summary>
        /// The decoder will return only flow control instructions (and filter the others internally).
        /// </summary>
        public const uint DF_RETURN_FC_ONLY = 4;

        /// <summary>
        /// The decoder will stop and return to the caller when the instruction 'CALL' (near and far) was decoded.
        /// </summary>
        public const uint DF_STOP_ON_CALL = 8;

        /// <summary>
        /// The decoder will stop and return to the caller when the instruction 'RET' (near and far) was decoded.
        /// </summary>
        public const uint DF_STOP_ON_RET = 0x10;

        /// <summary>
        /// The decoder will stop and return to the caller when the instruction system-call/ret was decoded.
        /// </summary>
        public const uint DF_STOP_ON_SYS = 0x20;

        /// <summary>
        /// The decoder will stop and return to the caller when any of the branch 'JMP', (near and far) instructions
        /// were decoded.
        /// </summary>
        public const uint DF_STOP_ON_UNC_BRANCH = 0x40;

        /// <summary>
        /// The decoder will stop and return to the caller when any of the conditional branch instruction were decoded.
        /// </summary>
        public const uint DF_STOP_ON_CND_BRANCH = 0x80;

        /// <summary>
        /// The decoder will stop and return to the caller when the instruction 'INT' (INT, INT1, INTO, INT 3) was
        /// decoded.
        /// </summary>
        public const uint DF_STOP_ON_INT = 0x100;

        /// <summary>
        /// The decoder will stop and return to the caller when any of the 'CMOVxx' instruction was decoded.
        /// </summary>
        public const uint DF_STOP_ON_CMOV = 0x200;

        /// <summary>
        /// The decoder will stop and return to the caller when any flow control instruction was decoded.
        /// </summary>
        public const uint DF_STOP_ON_FLOW_CONTROL = (DF_STOP_ON_CALL | DF_STOP_ON_RET | DF_STOP_ON_SYS |
                                                     DF_STOP_ON_UNC_BRANCH | DF_STOP_ON_CND_BRANCH | DF_STOP_ON_INT |
                                                     DF_STOP_ON_CMOV);

        #endregion

        #region Flow control flags

        /// <summary>
        /// Indicates the instruction is not a flow-control instruction.
        /// </summary>
        public const uint FC_NONE = 0;

        /// <summary>
        /// Indicates the instruction is one of: CALL, CALL FAR.
        /// </summary>
        public const uint FC_CALL = 1;

        /// <summary>
        /// Indicates the instruction is one of: RET, IRET, RETF.
        /// </summary>
        public const uint FC_RET = 2;

        /// <summary>
        /// Indicates the instruction is one of: SYSCALL, SYSRET, SYSENTER, SYSEXIT.
        /// </summary>
        public const uint FC_SYS = 3;

        /// <summary>
        /// Indicates the instruction is one of: JMP, JMP FAR.
        /// </summary>
        public const uint FC_UNC_BRANCH = 4;

        /// <summary>
        /// Indicates the instruction is one of:
        /// JCXZ, JO, JNO, JB, JAE, JZ, JNZ, JBE, JA, JS, JNS, JP, JNP, JL, JGE, JLE, JG, LOOP, LOOPZ, LOOPNZ.
        /// </summary>
        public const uint FC_CND_BRANCH = 5;

        /// <summary>
        /// Indiciates the instruction is one of: INT, INT1, INT 3, INTO, UD2.
        /// </summary>
        public const uint FC_INT = 6;

        /// <summary>
        /// Indicates the instruction is one of: CMOVxx.
        /// </summary>
        public const uint FC_CMOV = 7;

        #endregion

        #region Miscellaneous constants

        /// <summary>
        /// No register was defined.
        /// </summary>
        public const byte R_NONE = unchecked((byte)-1);

        /// <summary>
        /// Up to four operands per instruction.
        /// </summary>
        public const byte OPERANDS_NO = 4;

        #endregion

        #endregion

        #region Enumerations

        /// <summary>
        /// The three types of processor types that can be decoded.
        /// </summary>
        public enum _DecodeType
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
        public enum _DecodeResult
        {
            /// <summary>
            /// Nothing was decoded.
            /// </summary>
            DECRES_NONE,

            /// <summary>
            /// The decoding was successful.
            /// </summary>
            DECRES_SUCCESS,
            
            /// <summary>
            /// There are not enough entries to use in the result array.
            /// </summary>
            DECRES_MEMORYERR,

            /// <summary>
            /// Input error (null code buffer, invalid decoding mode, etc...).
            /// </summary>
            DECRES_INPUTERR,

            /// <summary>
            /// The decode result was filtered.
            /// </summary>
            DECRES_FILTERED
        }

        #endregion

        #region Methods

        /// <summary>
        /// Decomposes data into assembly format, using the native distorm_decompose function.
        /// </summary>
        /// <param name="ci">
        /// The _CodeInfo structure that holds the data that will be decomposed.
        /// </param>
        /// <param name="result">
        /// Array of type _DInst which will be used by this function in order to return the disassembled instructions.
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
        /// DECRES_SUCCESS on success (no more to disassemble), DECRES_INPUTERR on input error (null code buffer,
        /// invalid decoding mode, etc...), DECRES_MEMORYERR when there are not enough entries to use in the result
        /// array, BUT YOU STILL have to check for usedInstructionsCount!
        /// </returns>
        /// <remarks>
        /// Side-Effects: Even if the return code is DECRES_MEMORYERR, there might STILL be data in the array you
        ///               passed, this function will try to use as much entries as possible!
        /// Notes: 1) The minimal size of maxInstructions is 15.
        ///        2) You will have to synchronize the offset,code and length by yourself if you pass code fragments
        ///           and not a complete code block!
        /// </remarks>
        [DllImport("distorm3.dll", CharSet = CharSet.Ansi, CallingConvention = CallingConvention.Cdecl,
#if _WIN64
            EntryPoint = "distorm_decompose64")]
#else
            EntryPoint = "distorm_decompose32")]
#endif
        public static extern _DecodeResult distorm_decompose(
            ref _CodeInfo ci, [In, Out] _DInst[] result, uint maxInstructions, ref uint usedInstructionsCount);

        /// <summary>
        /// Convert a _DInst structure, which was produced from the distorm_decompose function, into text.
        /// </summary>
        /// <param name="ci">The _CodeInfo structure that holds the data that was decomposed.</param>
        /// <param name="di">The decoded instruction.</param>
        /// <param name="result">The variable to which the formatted instruction will be returned.</param>
        [DllImport("distorm3.dll", CharSet = CharSet.Ansi, CallingConvention = CallingConvention.Cdecl,
#if _WIN64
            EntryPoint = "distorm_format64")]
#else
            EntryPoint = "distorm_format32")]
#endif
        public static extern void distorm_format(ref _CodeInfo ci, ref _DInst di, ref _DecodedInst result);

        #endregion

        #region Structures

        /// <summary>
        /// Static size of strings. Do not change this value. Keep Python wrapper in sync.
        /// </summary>
        [StructLayout(LayoutKind.Sequential)]
        public struct _WString
        {
            /// <summary>
            /// The length of p.
            /// </summary>
            public uint length;

            /// <summary>
            /// A null terminated string.
            /// </summary>
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 48)]
            public byte[] p;
        }

        /// <summary>
        /// Old decoded instruction structure in text format.
        /// Used only for backward compatibility with diStorm64.
        /// This structure holds all information the disassembler generates per instruction.
        /// </summary>
        [StructLayout(LayoutKind.Sequential)]
        public struct _DecodedInst
        {
            /// <summary>
            /// Mnemonic of decoded instruction, prefixed if required by REP, LOCK etc.
            /// </summary>
            private _WString mnemonic;

            /// <summary>
            /// Operands of the decoded instruction, up to 3 operands, comma-seperated.
            /// </summary>
            private _WString operands;

            /// <summary>
            /// Hex dump - little endian, including prefixes.
            /// </summary>
            private _WString instructionHex;

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
                    return longOperands.Substring(0, (int)this.operands.length).ToLower();
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
        public struct _Operand
        {
            /// <summary>
            /// Type of operand:
            /// O_NONE: operand is to be ignored.
            /// O_REG: index holds global register index.
            /// O_IMM: instruction.imm.
            /// O_IMM1: instruction.imm.ex.i1.
            /// O_IMM2: instruction.imm.ex.i2.
            /// O_DISP: memory dereference with displacement only, instruction.disp.
            /// O_SMEM: simple memory dereference with optional displacement (a single register memory dereference).
            /// O_MEM: complex memory dereference (optional fields: s/i/b/disp).
            /// O_PC: the relative address of a branch instruction (instruction.imm.addr).
            /// O_PTR: the absolute target address of a far branch instruction (instruction.imm.ptr.seg/off).
            /// </summary>
            public byte type;

            /// <summary>
            /// Index of:
            /// O_REG: holds global register index
            /// O_SMEM: holds the 'base' register. E.G: [ECX], [EBX+0x1234] are both in operand.index.
            /// O_MEM: holds the 'index' register. E.G: [EAX*4] is in operand.index.
            /// </summary>
            public byte index;

            /// <summary>
            /// Size of:
            /// O_REG: register
            /// O_IMM: instruction.imm
            /// O_IMM1: instruction.imm.ex.i1
            /// O_IMM2: instruction.imm.ex.i2
            /// O_DISP: instruction.disp
            /// O_SMEM: size of indirection.
            /// O_MEM: size of indirection.
            /// O_PC: size of the relative offset
            /// O_PTR: size of instruction.imm.ptr.off (16 or 32)
            /// </summary>
            public ushort size;
        }

        /// <summary>
        /// Used by O_PTR.
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
        /// Used by O_IMM1 (i1) and O_IMM2 (i2). ENTER instruction only.
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
            /// The value, as an address. Used by O_PC: (Use GET_TARGET_ADDR).
            /// </summary>
            [FieldOffset(0)]
            public ulong addr;

            /// <summary>
            /// The value, as a pointer. Used by O_PTR.
            /// </summary>
            [FieldOffset(0)]
            public _Value_ptr ptr;

            /// <summary>
            /// Used by O_IMM1 (i1) and O_IMM2 (i2). ENTER instruction only.
            /// </summary>
            [FieldOffset(0)]
            public _Value_ex ex;
        }

        /// <summary>
        /// Represents the new decoded instruction, used by the decompose interface.
        /// </summary>
        [StructLayout(LayoutKind.Sequential)]
        public struct _DInst
        {
            /// <summary>
            /// The immediate value of the instruction.
            /// Used by ops[n].type == O_IMM/O_IMM1&O_IMM2/O_PTR/O_PC. Its size is ops[n].size.
            /// </summary>
            public _Value imm;

            /// <summary>
            /// Used by ops[n].type == O_SMEM/O_MEM/O_DISP. Its size is dispSize.
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
            /// Up to four operands per instruction, ignored if ops[n].type == O_NONE.
            /// </summary>
            [MarshalAs(UnmanagedType.ByValArray, ArraySubType = UnmanagedType.I4, SizeConst = OPERANDS_NO)]
            public _Operand[] ops;

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
            /// Used by ops[n].type == O_MEM. Base global register index (might be R_NONE), scale size (2/4/8), ignored
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
        }

        /// <summary>
        /// Holds various pieces of information that are required by the distorm_decompose function.
        /// </summary>
        [StructLayout(LayoutKind.Sequential)]
        public struct _CodeInfo
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
            public _DecodeType dt;

            /// <summary>
            /// Features that should be enabled during decomposition. Relevant flags begin with DF_.
            /// </summary>
            public uint features;
        }

        #endregion
    }
}
