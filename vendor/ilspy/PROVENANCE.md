# ILSpy managed worker dependency

ICSharpCode.Decompiler 11.0.0.9375, upstream ILSpy v11.0, MIT license.
The unmodified NuGet package is restored from https://api.nuget.org/v3/index.json
using the committed worker packages.lock.json content hash. Upstream source:
https://github.com/icsharpcode/ILSpy/tree/v11.0/ICSharpCode.Decompiler

The private build uses Microsoft .NET SDK 10.0.400 (checksum pinned by
tools/bootstrap-managed-sdk.ps1). The self-contained .NET 10.0.11 runtime is
published separately for win-x64 and linux-x64; its license and third-party notices
are retained with the payload. No target assembly is executed. The C++ application
invokes this worker through its bounded native process runner.
