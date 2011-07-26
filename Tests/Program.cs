//-----------------------------------------------------------------------
// <copyright file="Program.cs">
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

namespace Tests
{
    using System;
    using System.Collections.Generic;
    using System.Linq;
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
            IntPtr codePtr = Marshal.AllocHGlobal(code.Length);
            Marshal.Copy(code, 0, codePtr, code.Length);

            // Prepare the _CodeInfo structure for decomposition.
            Distorm._CodeInfo ci = new Distorm._CodeInfo();
            ci.codeLen = code.Length;
            ci.code = codePtr;
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

            // Free the previously allocated unmanaged code.
            Marshal.FreeHGlobal(codePtr);

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
