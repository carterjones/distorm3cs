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
        public static bool VerifyDecomposition(DistormSimple.DInst[] result)
        {
            if (result.Length < 6)
            {
                return false;
            }

            // Manually check each instruction.
            if (result[0].InstructionType != DistormSimple.InstructionType.PUSH ||
                result[0].ops[0].RegisterName != "ebp")
            {
                return false;
            }
            else if (result[1].InstructionType != DistormSimple.InstructionType.MOV ||
                result[1].ops[0].RegisterName != "ebp" ||
                result[1].ops[1].RegisterName != "esp")
            {
                return false;
            }
            else if (result[2].InstructionType != DistormSimple.InstructionType.MOV ||
                result[2].ops[0].RegisterName != "eax" ||
                result[2].ops[1].type != DistormSimple.OperandType.SMEM ||
                result[2].ops[1].RegisterName != "ebp" ||
                result[2].disp != 0x8)
            {
                return false;
            }
            else if (result[3].InstructionType != DistormSimple.InstructionType.ADD ||
                result[3].ops[0].RegisterName != "eax" ||
                result[3].ops[1].type != DistormSimple.OperandType.SMEM ||
                result[3].ops[1].RegisterName != "ebp" ||
                result[3].disp != 0xc)
            {
                return false;
            }
            else if (result[4].InstructionType != DistormSimple.InstructionType.LEAVE)
            {
                return false;
            }
            else if (result[5].InstructionType != DistormSimple.InstructionType.RET)
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
                                    "leave \n" +
                                    "ret \n";
            string actualOutput = string.Empty;

            GCHandle gch = GCHandle.Alloc(Program.code, GCHandleType.Pinned);

            // Prepare the _CodeInfo structure for decomposition.
            Distorm._CodeInfo ci = new Distorm._CodeInfo();
            ci.codeLen = Program.code.Length;
            ci.code = gch.AddrOfPinnedObject();
            ci.codeOffset = 0;
            ci.dt = Distorm._DecodeType.Decode32Bits;
            ci.features = Distorm.DF_NONE;
            
            // Prepare the result instruction buffer to receive the decomposition.
            Distorm._DInst[] result = new Distorm._DInst[Program.code.Length];
            uint usedInstructionsCount = 0;

            // Perform the decomposition.
            Distorm._DecodeResult r =
                Distorm.distorm_decompose(ref ci, result, (uint)result.Length, ref usedInstructionsCount);

            // Release the handle pinned to the code.
            gch.Free();

            // Return false if an error occured during decomposition.
            if (!r.Equals(Distorm._DecodeResult.DECRES_SUCCESS))
            {
                return false;
            }

            // Prepare a _DecodedInst structure for formatting the results.
            Distorm._DecodedInst inst = new Distorm._DecodedInst();

            for (uint i = 0; i < usedInstructionsCount; ++i)
            {
                // Format the results of the decomposition.
                Distorm.distorm_format(ref ci, ref result[i], ref inst);

                // Add it to the buffer to be verified.
                actualOutput += inst.Mnemonic + " " + inst.Operands + "\n";
            }

            return expectedOutput.Equals(actualOutput);
        }

        /// <summary>
        /// Tests the DistormSimple.distorm_decompose() function.
        /// </summary>
        /// <returns>Returns true if the test passed.</returns>
        public static bool DecomposeOnlyTest()
        {
            GCHandle gch = GCHandle.Alloc(Program.code, GCHandleType.Pinned);

            DistormSimple.CodeInfo ci = new DistormSimple.CodeInfo();
            ci.codeLen = Program.code.Length;
            ci.code = gch.AddrOfPinnedObject();
            ci.codeOffset = 0;
            ci.dt = DistormSimple.DecodeType.Decode32Bits;
            ci.features = Distorm.DF_NONE;

            DistormSimple.DInst[] result = new DistormSimple.DInst[Program.code.Length];
            uint usedInstructionsCount = 0;

            DistormSimple.DecodeResult r =
                DistormSimple.distorm_decompose(ref ci, result, (uint)result.Length, ref usedInstructionsCount);

            // Release the handle pinned to the code.
            gch.Free();

            // Return false if an error occured during decomposition.
            if (!r.Equals(DistormSimple.DecodeResult.SUCCESS))
            {
                return false;
            }

            if (usedInstructionsCount < 6)
            {
                return false;
            }

            // Manually check each instruction.
            if (result[0].InstructionType != DistormSimple.InstructionType.PUSH ||
                result[0].ops[0].RegisterName != "ebp")
            {
                return false;
            }
            else if (result[1].InstructionType != DistormSimple.InstructionType.MOV ||
                result[1].ops[0].RegisterName != "ebp" ||
                result[1].ops[1].RegisterName != "esp")
            {
                return false;
            }
            else if (result[2].InstructionType != DistormSimple.InstructionType.MOV ||
                result[2].ops[0].RegisterName != "eax" ||
                result[2].ops[1].type != DistormSimple.OperandType.SMEM ||
                result[2].ops[1].RegisterName != "ebp" ||
                result[2].disp != 0x8)
            {
                return false;
            }
            else if (result[3].InstructionType != DistormSimple.InstructionType.ADD ||
                result[3].ops[0].RegisterName != "eax" ||
                result[3].ops[1].type != DistormSimple.OperandType.SMEM ||
                result[3].ops[1].RegisterName != "ebp" ||
                result[3].disp != 0xc)
            {
                return false;
            }
            else if (result[4].InstructionType != DistormSimple.InstructionType.LEAVE)
            {
                return false;
            }
            else if (result[5].InstructionType != DistormSimple.InstructionType.RET)
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
            DistormSimple.DInst[] result = DistormSimple.Decompose(Program.code);

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

            DistormSimple.DInst[] insts = DistormSimple.Decompose(incompleteCode);
            if (insts.Length < 6)
            {
                return false;
            }
            else if (insts[5].InstructionType != DistormSimple.InstructionType.UNDEFINED)
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
