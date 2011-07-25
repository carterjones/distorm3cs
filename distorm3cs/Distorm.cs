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
    using System.Runtime.InteropServices;
    using System.Text;

    /// <summary>
    /// The primary interface for calling distorm3 functions.
    /// </summary>
    public class Distorm
    {
        #region Constants

        public const uint DF_NONE = 0;

        #endregion

        #region Enumerations

        public enum _DecodeType
        {
            Decode16Bits = 0,
            Decode32Bits = 1,
            Decode64Bits = 2
        }

        /// <summary>
        /// Return code of the decoding function.
        /// </summary>
        public enum _DecodeResult
        {
            DECRES_NONE,
            DECRES_SUCCESS,
            DECRES_MEMORYERR,
            DECRES_INPUTERR,
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
        [DllImport("distorm3.dll", CharSet = CharSet.Ansi)]
#if _WIN64
        public static extern uint distorm_decompose64(
#else
        public static extern uint distorm_decompose32(
#endif
            ref _CodeInfo ci,
            [In, Out] _DInst[] result,
            uint maxInstructions,
            ref uint usedInstructionsCount);

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
            public ushort seg;

            /// <summary>
            /// Can be 16 or 32 bits, size is in ops[n].size.
            /// </summary>
            public uint off;
        }

        /// <summary>
        /// Used by O_IMM1 (i1) and O_IMM2 (i2). ENTER instruction only.
        /// </summary>
        [StructLayout(LayoutKind.Sequential)]
        public struct _Value_ex
        {
            public uint i1;
            public uint i2;
        }

        /// <summary>
        /// Represents a value within an instruction.
        /// </summary>
        [StructLayout(LayoutKind.Explicit)]
        public struct _Value
        {
            [FieldOffset(0)]
            public sbyte sbyte_;
            [FieldOffset(0)]
            public byte byte_;
            [FieldOffset(0)]
            public short sword;
            [FieldOffset(0)]
            public ushort word;
            [FieldOffset(0)]
            public int sdword;
            [FieldOffset(0)]
            public uint dword;

            /// <summary>
            /// All immediates are SIGN-EXTENDED to 64 bits!
            /// </summary>
            [FieldOffset(0)]
            public long sqword;
            [FieldOffset(0)]
            public ulong qword;

            /// <summary>
            /// Used by O_PC: (Use GET_TARGET_ADDR).
            /// </summary>
            [FieldOffset(0)]
            public ulong addr;

            /// <summary>
            /// Used by O_PTR.
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
            public _Operand op1;
            public _Operand op2;
            public _Operand op3;
            public _Operand op4;

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

            public byte dispSize;

            /// <summary>
            /// Meta defines the instruction set class, and the flow control flags. Use META macros.
            /// </summary>
            public byte meta;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct _CodeInfo
        {
            public ulong codeOffset, nextOffset;
            public byte[] code;
            public int codeLen;
            public _DecodeType dt;
            public uint features;
        }

        #endregion
    }
}
