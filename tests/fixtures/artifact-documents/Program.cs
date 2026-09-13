using OpenMcdf;
using System.Text;
Directory.CreateDirectory(args[0]);
using var root=RootStorage.Create(Path.Combine(args[0],"fixture.ole"),OpenMcdf.Version.V3,StorageModeFlags.None);
using var stream=root.CreateStream("inert");stream.Write(Encoding.UTF8.GetBytes("indago OLE marker"));
