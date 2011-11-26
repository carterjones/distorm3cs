namespace Tests
{
    using System;
    using System.Collections.Generic;
    using System.Linq;
    using System.Runtime;
    using System.Runtime.InteropServices;
    using System.Text;
    using distorm3cs;

    /// <summary>
    /// Tests various functionality of the distorm3cs interface.
    /// </summary>
    public class Program
    {
        /// <summary>
        /// Tests both the distorm_decompose and distorm_format functions.
        /// </summary>
        /// <returns>Returns true if both tests passed.</returns>
        public static bool DecomposeFormat()
        {
            string expectedOutput = "push ebp\n" +
                                    "mov ebp, esp\n" +
                                    "mov eax, [ebp+0x8]\n" +
                                    "add eax, [ebp+0xc]\n" +
                                    "leave \n" +
                                    "ret \n";
            string actualOutput = string.Empty;

            // This byte sample is available/examined at: http://code.google.com/p/distorm/wiki/Showcases
            byte[] code = new byte[] { 0x55, 0x8b, 0xec, 0x8b, 0x45, 0x08, 0x03, 0x45, 0x0c, 0xc9, 0xc3 };
            GCHandle gch = GCHandle.Alloc(code, GCHandleType.Pinned);

            // Prepare the _CodeInfo structure for decomposition.
            Distorm._CodeInfo ci = new Distorm._CodeInfo();
            ci.codeLen = code.Length;
            ci.code = gch.AddrOfPinnedObject();
            ci.codeOffset = 0;
            ci.dt = Distorm._DecodeType.Decode32Bits;
            ci.features = Distorm.DF_NONE;
            
            // Prepare the result instruction buffer to receive the decomposition.
            Distorm._DInst[] result = new Distorm._DInst[10];
            uint usedInstructionsCount = 0;

            // Perform the decomposition.
            Distorm._DecodeResult r =
                Distorm.distorm_decompose(ref ci, result, (uint)result.Length, ref usedInstructionsCount);

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

            // Release the handle pinned to the code.
            gch.Free();

            return expectedOutput.Equals(actualOutput);
        }

        /// <summary>
        /// Runs the collection of tests of the distorm3cs interface.
        /// </summary>
        /// <param name="args">Command line arguments passed to the program.</param>
        private static void Main(string[] args)
        {
            Console.WriteLine("DecomposeFormat(): " + (Program.DecomposeFormat() ? "Passed" : "Failed"));

            Console.ReadKey();
        }
    }
}
