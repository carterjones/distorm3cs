namespace Tests
{
    using System;
    using System.Collections.Generic;
    using System.Linq;
    using System.Runtime;
    using System.Runtime.InteropServices;
    using System.Text;
    using Distorm3cs;

    /// <summary>
    /// Tests various functionality of the distorm3cs interface.
    /// </summary>
    public class Program
    {
        /// <summary>
        /// The code that is used for testing decomposition.
        /// </summary>
        /// <remarks>
        /// This byte sample is available/examined at: http://code.google.com/p/distorm/wiki/Showcases
        /// </remarks>
        private static byte[] code = new byte[] { 0x55, 0x8b, 0xec, 0x8b, 0x45, 0x08, 0x03, 0x45, 0x0c, 0xc9, 0xc3 };

        /// <summary>
        /// Tests the decomposition of a resulting array that has parsed the test code in this class.
        /// </summary>
        /// <param name="result">The parsed results.</param>
        /// <returns>Returns true if the results have been parsed as expected.</returns>
        public static bool VerifyDecomposition(Distorm.DInst[] result)
        {
            if (result.Length < 6)
            {
                return false;
            }

            // Manually check each instruction.
            if (result[0].InstructionType != Distorm.InstructionType.PUSH ||
                result[0].ops[0].RegisterName != "ebp")
            {
                return false;
            }
            else if (result[1].InstructionType != Distorm.InstructionType.MOV ||
                result[1].ops[0].RegisterName != "ebp" ||
                result[1].ops[1].RegisterName != "esp")
            {
                return false;
            }
            else if (result[2].InstructionType != Distorm.InstructionType.MOV ||
                result[2].ops[0].RegisterName != "eax" ||
                result[2].ops[1].type != Distorm.OperandType.SMEM ||
                result[2].ops[1].RegisterName != "ebp" ||
                result[2].disp != 0x8)
            {
                return false;
            }
            else if (result[3].InstructionType != Distorm.InstructionType.ADD ||
                result[3].ops[0].RegisterName != "eax" ||
                result[3].ops[1].type != Distorm.OperandType.SMEM ||
                result[3].ops[1].RegisterName != "ebp" ||
                result[3].disp != 0xc)
            {
                return false;
            }
            else if (result[4].InstructionType != Distorm.InstructionType.LEAVE)
            {
                return false;
            }
            else if (result[5].InstructionType != Distorm.InstructionType.RET)
            {
                return false;
            }

            return true;
        }

        /// <summary>
        /// Tests both the distorm_decompose and distorm_format functions.
        /// </summary>
        /// <returns>Returns true if both tests passed.</returns>
        public static bool DecomposeFormatTest()
        {
            string expectedOutput = "push ebp\n" +
                                    "mov ebp, esp\n" +
                                    "mov eax, [ebp+0x8]\n" +
                                    "add eax, [ebp+0xc]\n" +
                                    "leave\n" +
                                    "ret\n";
            string actualOutput = string.Empty;

            GCHandle gch = GCHandle.Alloc(Program.code, GCHandleType.Pinned);

            // Prepare the _CodeInfo structure for decomposition.
            DistormOriginal._CodeInfo ci = new DistormOriginal._CodeInfo();
            ci.codeLen = Program.code.Length;
            ci.code = gch.AddrOfPinnedObject();
            ci.codeOffset = 0;
            ci.dt = DistormOriginal._DecodeType.Decode32Bits;
            ci.features = DistormOriginal.DF_NONE;
            
            // Prepare the result instruction buffer to receive the decomposition.
            DistormOriginal._DInst[] result = new DistormOriginal._DInst[Program.code.Length];
            uint usedInstructionsCount = 0;

            // Perform the decomposition.
            DistormOriginal._DecodeResult r =
                DistormOriginal.distorm_decompose(ref ci, result, (uint)result.Length, ref usedInstructionsCount);

            // Release the handle pinned to the code.
            gch.Free();

            // Return false if an error occured during decomposition.
            if (!r.Equals(DistormOriginal._DecodeResult.DECRES_SUCCESS))
            {
                return false;
            }

            // Prepare a _DecodedInst structure for formatting the results.
            DistormOriginal._DecodedInst inst = new DistormOriginal._DecodedInst();

            for (uint i = 0; i < usedInstructionsCount; ++i)
            {
                // Format the results of the decomposition.
                DistormOriginal.distorm_format(ref ci, ref result[i], ref inst);

                // Add it to the buffer to be verified.
                if (string.IsNullOrEmpty(inst.Operands))
                {
                    actualOutput += inst.Mnemonic + "\n";
                }
                else
                {
                    actualOutput += inst.Mnemonic + " " + inst.Operands + "\n";
                }
            }

            return expectedOutput.Equals(actualOutput);
        }

        /// <summary>
        /// Tests the DistormSimple.Disassemble function.
        /// </summary>
        /// <returns>Returns true if the test passed.</returns>
        public static bool DisassembleTest()
        {
            string expectedOutput = "push ebp\n" +
                                    "mov ebp, esp\n" +
                                    "mov eax, [ebp+0x8]\n" +
                                    "add eax, [ebp+0xc]\n" +
                                    "leave\n" +
                                    "ret\n";

            List<string> instructions = Distorm.Disassemble(Program.code);

            return expectedOutput.Equals(string.Join("\n", instructions) + "\n");
        }

        /// <summary>
        /// Tests the DistormSimple.distorm_decompose() function.
        /// </summary>
        /// <returns>Returns true if the test passed.</returns>
        public static bool DecomposeOnlyTest()
        {
            GCHandle gch = GCHandle.Alloc(Program.code, GCHandleType.Pinned);

            Distorm.CodeInfo ci = new Distorm.CodeInfo();
            ci.codeLen = Program.code.Length;
            ci.code = gch.AddrOfPinnedObject();
            ci.codeOffset = 0;
            ci.dt = Distorm.DecodeType.Decode32Bits;
            ci.features = DistormOriginal.DF_NONE;

            Distorm.DInst[] result = new Distorm.DInst[Program.code.Length];
            uint usedInstructionsCount = 0;

            Distorm.DecodeResult r =
                Distorm.distorm_decompose(ref ci, result, (uint)result.Length, ref usedInstructionsCount);

            // Release the handle pinned to the code.
            gch.Free();

            // Return false if an error occured during decomposition.
            if (!r.Equals(Distorm.DecodeResult.SUCCESS))
            {
                return false;
            }

            if (usedInstructionsCount < 6)
            {
                return false;
            }

            // Manually check each instruction.
            if (result[0].InstructionType != Distorm.InstructionType.PUSH ||
                result[0].ops[0].RegisterName != "ebp")
            {
                return false;
            }
            else if (result[1].InstructionType != Distorm.InstructionType.MOV ||
                result[1].ops[0].RegisterName != "ebp" ||
                result[1].ops[1].RegisterName != "esp")
            {
                return false;
            }
            else if (result[2].InstructionType != Distorm.InstructionType.MOV ||
                result[2].ops[0].RegisterName != "eax" ||
                result[2].ops[1].type != Distorm.OperandType.SMEM ||
                result[2].ops[1].RegisterName != "ebp" ||
                result[2].disp != 0x8)
            {
                return false;
            }
            else if (result[3].InstructionType != Distorm.InstructionType.ADD ||
                result[3].ops[0].RegisterName != "eax" ||
                result[3].ops[1].type != Distorm.OperandType.SMEM ||
                result[3].ops[1].RegisterName != "ebp" ||
                result[3].disp != 0xc)
            {
                return false;
            }
            else if (result[4].InstructionType != Distorm.InstructionType.LEAVE)
            {
                return false;
            }
            else if (result[5].InstructionType != Distorm.InstructionType.RET)
            {
                return false;
            }

            return true;
        }

        /// <summary>
        /// Tests the DistormSimple.Decompose() function.
        /// </summary>
        /// <returns>Returns true if the test passed.</returns>
        public static bool DecomposeWrapperTest()
        {
            Distorm.DInst[] result = Distorm.Decompose(Program.code);

            return Program.VerifyDecomposition(result);
        }

        /// <summary>
        /// Tests the DistormSimple.Decompose() function, but with an incomplete code buffer. This assumes that the
        /// DistormSimple.Decompose() function works properly with a properly made code buffer.
        /// </summary>
        /// <returns>Returns true if the test passed.</returns>
        public static bool DecomposeWrapperIncompleteCodeTest()
        {
            byte[] incompleteCode = new byte[Program.code.Length];
            Array.Copy(code, incompleteCode, incompleteCode.Length - 1);

            // Set the last byte to the first part of a "mov ebp, esp" instruction.
            incompleteCode[incompleteCode.Length - 1] = 0x8b;

            Distorm.DInst[] insts = Distorm.Decompose(incompleteCode);
            if (insts.Length < 6)
            {
                return false;
            }
            else if (insts[5].InstructionType != Distorm.InstructionType.UNDEFINED)
            {
                return false;
            }

            return true;
        }

        /// <summary>
        /// Runs the collection of tests of the distorm3cs interface.
        /// </summary>
        /// <param name="args">Command line arguments passed to the program.</param>
        private static void Main(string[] args)
        {
            bool result = true;
            bool tmpResult = false;

            result &= tmpResult = Program.DecomposeFormatTest();
            Console.WriteLine("DecomposeFormatTest():                " + (tmpResult ? "Passed" : "Failed"));
            result &= tmpResult = Program.DisassembleTest();
            Console.WriteLine("DisassembleTest():                    " + (tmpResult ? "Passed" : "Failed"));
            result &= tmpResult = Program.DecomposeOnlyTest();
            Console.WriteLine("DecomposeOnlyTest():                  " + (tmpResult ? "Passed" : "Failed"));
            result &= tmpResult = Program.DecomposeWrapperTest();
            Console.WriteLine("DecomposeWrapperTest():               " + (tmpResult ? "Passed" : "Failed"));
            result &= tmpResult = Program.DecomposeWrapperIncompleteCodeTest();
            Console.WriteLine("DecomposeWrapperIncompleteCodeTest(): " + (tmpResult ? "Passed" : "Failed"));

            Console.WriteLine("--------------------------------------------");
            Console.WriteLine("End result:                           " + (result ? "All passed" : "Not all passed"));

            Console.WriteLine();
            Console.WriteLine("Press any key to continue.");
            Console.ReadKey();
        }
    }
}
