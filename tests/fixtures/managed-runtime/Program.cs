using System;
using System.Runtime.CompilerServices;
internal static class Program {
    [MethodImpl(MethodImplOptions.NoInlining)] static int Work(int n) {try {throw new InvalidOperationException("indago-observed-exception");}catch(InvalidOperationException){return n+17;}}
    static void Main(){Console.WriteLine(Work(25));}
}
