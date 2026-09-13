using System.Reflection.Metadata;
using System.Reflection.PortableExecutable;
using System.Security.Cryptography;
using System.Text.Json.Nodes;
using ICSharpCode.Decompiler.Metadata;
using ManagedPE = ICSharpCode.Decompiler.Metadata.PEFile;

// Only hash-pinned snapshots explicitly supplied by the native project store.
internal sealed class ImportedResolver : IAssemblyResolver, IDisposable
{
    private readonly Dictionary<string, ManagedPE> modules = new(StringComparer.OrdinalIgnoreCase);
    private readonly Dictionary<MetadataFile, string> hashes = new();
    public int RequestCount { get; private set; }
    public int ResolvedCount { get; private set; }
    public JsonArray Inventory() {
        var result=new JsonArray();
        foreach(var pair in modules)result.Add(new JsonObject {["assembly_identity"]=pair.Key,["artifact_sha256"]=hashes[pair.Value]});
        return result;
    }
    public static string Identity(string name, Version version, string culture, byte[] token) =>
        $"{name}, Version={version}, Culture={(culture.Length==0?"neutral":culture)}, PublicKeyToken={(token.Length==0?"null":Convert.ToHexStringLower(token))}";
    public static string Identity(MetadataReader m) {
        var a=m.GetAssemblyDefinition();var key=m.GetBlobBytes(a.PublicKey);
        byte[] token=key.Length==0?[]:SHA1.HashData(key)[^8..].Reverse().ToArray();
        return Identity(m.GetString(a.Name),a.Version,m.GetString(a.Culture),token);
    }
    public ImportedResolver(JsonArray? dependencies) {
        try {
            if(dependencies==null)return;
            if(dependencies.Count>8)throw new ArgumentException("At most eight imported dependencies");
            long total=0;
            foreach(var node in dependencies) {
                var d=node!.AsObject();string path=d["path"]!.GetValue<string>(),hash=d["sha256"]!.GetValue<string>();
                if(!Path.IsPathFullyQualified(path))throw new ArgumentException("Absolute dependency snapshot required");
                using var file=new FileStream(path,FileMode.Open,FileAccess.Read,FileShare.Read);
                if(file.Length<1||file.Length>16*1024*1024||(total+=file.Length)>32*1024*1024)throw new ArgumentException("Dependency byte bound exceeded");
                var bytes=new byte[(int)file.Length];file.ReadExactly(bytes);
                if(file.ReadByte()!=-1||Convert.ToHexStringLower(SHA256.HashData(bytes))!=hash)throw new ArgumentException("Dependency hash mismatch");
                var module=new ManagedPE(path,new MemoryStream(bytes,false),PEStreamOptions.PrefetchEntireImage);
                try {
                    if(!module.Metadata.IsAssembly)throw new ArgumentException("Dependency must be an assembly");
                    string identity=Identity(module.Metadata);
                    if(!modules.TryAdd(identity,module))throw new ArgumentException("Ambiguous duplicate dependency identity");
                    hashes.Add(module,hash);
                } catch {module.Dispose();throw;}
            }
        } catch {Dispose();throw;}
    }
    public string? Hash(MetadataFile? module) => module!=null&&hashes.TryGetValue(module,out var hash)?hash:null;
    public MetadataFile? Resolve(IAssemblyReference reference) {
        if(modules.TryGetValue(reference.FullName,out var module)){ResolvedCount++;return module;}
        RequestCount++;return null;
    }
    public string? ResolveIdentity(string identity) => modules.TryGetValue(identity,out var module)?Hash(module):null;
    public MetadataFile? ResolveModule(MetadataFile mainModule,string moduleName){RequestCount++;return null;}
    public Task<MetadataFile?> ResolveAsync(IAssemblyReference reference)=>Task.FromResult(Resolve(reference));
    public Task<MetadataFile?> ResolveModuleAsync(MetadataFile mainModule,string moduleName)=>Task.FromResult(ResolveModule(mainModule,moduleName));
    public void Dispose(){foreach(var module in modules.Values)module.Dispose();modules.Clear();hashes.Clear();}
}
