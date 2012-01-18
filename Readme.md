# distorm3cs
distorm3cs is a C# interface to distorm3.

Note: Currently, distorm3cs is in alpha status.

## Usage

The following use cases expect that the `code` variable is an array of bytes, which represents assembly instructions, as shown:

```C#
byte[] code = new byte[]
{
    0x55, 0x8b, 0xec, 0x8b, 0x45, 0x08, 0x03, 0x45, 0x0c, 0xc9, 0xc3
};
```

### Simple Interface

To decompose the instructions and receive an array of non-string results, a simple decomposition interface is also available:

```C#
DistormSimple.DInst[] result = DistormSimple.Decompose(code);
```

To disassemble the code and receive a list of strings that represent the decomposed instructions, call the `DistormSimple.Disassemble()` function. This disassembles the code bytes by using the `distorm_decompose()` function and then applies the `distorm_format()` function on top of that.

```C#
List<string> instructions = DistormSimple.Disassemble(code);
```

### Original Interface

Access to the original `distorm_decompose()` interface is also available. To decompose the code in a more granular way, the following method can be used:

```C#
GCHandle gch = GCHandle.Alloc(code, GCHandleType.Pinned);

DistormSimple.CodeInfo ci = new DistormSimple.CodeInfo();
ci.codeLen = code.Length;
ci.code = gch.AddrOfPinnedObject();
ci.codeOffset = 0;
ci.dt = DistormSimple.DecodeType.Decode32Bits;
ci.features = Distorm.DF_NONE;

DistormSimple.DInst[] result = new DistormSimple.DInst[code.Length];
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

// Perform any desired analysis on 'result' from this point forward.
```

The `distorm_format()` interface can be explicitly called, as well, producing the instructions in string format. The following code assumes that the `distorm_decompose()` function has been used to generate instructions that are stored in the `result[]` array:

```C#
// Prepare a _DecodedInst structure for formatting the results.
Distorm._DecodedInst inst = new Distorm._DecodedInst();

for (uint i = 0; i < usedInstructionsCount; ++i)
{
    // Format the results of the decomposition.
    Distorm.distorm_format(ref ci, ref result[i], ref inst);

    // Add it to the buffer to be verified.
    if (string.IsNullOrEmpty(inst.Operands))
    {
        output += inst.Mnemonic + "\n";
    }
    else
    {
        output += inst.Mnemonic + " " + inst.Operands + "\n";
    }
}
```
