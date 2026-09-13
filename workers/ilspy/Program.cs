using System.Globalization;
using System.Reflection.Metadata;
using System.Reflection.Metadata.Ecma335;
using System.Reflection.PortableExecutable;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json.Nodes;
using ICSharpCode.Decompiler;
using ICSharpCode.Decompiler.CSharp;
using ICSharpCode.Decompiler.CSharp.OutputVisitor;
using ICSharpCode.Decompiler.Disassembler;
using ICSharpCode.Decompiler.Metadata;
using ICSharpCode.Decompiler.TypeSystem;
using ManagedPE = ICSharpCode.Decompiler.Metadata.PEFile;

// The worker parses metadata; it never loads a target as an executable assembly.
internal static class Program
{
    private const int InputLimit = 16 * 1024 * 1024;
    private static string Short(string text) => text.Length <= 512 ? text : text[..512];
    private static int Number(JsonObject request, string key, int fallback, int minimum, int maximum)
    {
        int value = request[key]?.GetValue<int>() ?? fallback;
        if (value < minimum || value > maximum) throw new ArgumentException("Invalid " + key);
        return value;
    }
    private static JsonObject Location(EntityHandle handle) => new()
    {
        ["address_space"] = "managed_metadata", ["address"] = $"0x{MetadataTokens.GetToken(handle):x8}"
    };
    private static JsonObject Method(MetadataReader metadata, MethodDefinitionHandle handle)
    {
        var method = metadata.GetMethodDefinition(handle);
        return new JsonObject
        {
            ["token"] = $"0x{MetadataTokens.GetToken(handle):x8}",
            ["name"] = Short(metadata.GetString(method.Name)),
            ["name_truncated"] = metadata.GetString(method.Name).Length > 512,
            ["declaring_type"] = $"0x{MetadataTokens.GetToken(method.GetDeclaringType()):x8}",
            ["location"] = Location(handle), ["body_rva"] = method.RelativeVirtualAddress,
            ["attributes"] = method.Attributes.ToString(), ["implementation_attributes"] = method.ImplAttributes.ToString()
        };
    }
    public static int Main(string[] args)
    {
        JsonObject response = new() { ["backend"] = "ilspy", ["backend_version"] = "11.0.0.9375",
            ["schema"] = "indago.ilspy-worker.v1", ["status"] = "failed",
            ["target_executed"] = false, ["dependency_resolution"] = "disabled",
            ["token_mapping_complete"] = false, ["memory_limit_enforced"] = false };
        int outputLimit = 65536;
        try
        {
            if (args.Length != 1 || Encoding.UTF8.GetByteCount(args[0]) > 32768)
                throw new ArgumentException("One bounded JSON request required");
            var request = JsonNode.Parse(args[0]) as JsonObject ?? throw new ArgumentException("Object required");
            var allowed = new HashSet<string> { "path", "sha256", "operation", "token", "limit", "offset", "wall_ms", "output_bytes", "dependencies", "pdb", "entry", "output_path" };
            if (request.Any(field => !allowed.Contains(field.Key))) throw new ArgumentException("Unknown request field");
            outputLimit = Number(request, "output_bytes", 65536, 4096, 3145728);
            int limit = Number(request, "limit", 32, 1, 128), offset = Number(request, "offset", 0, 0, 1000000);
            using var deadline = new CancellationTokenSource(Number(request, "wall_ms", 10000, 1, 60000));
            var cancellation = deadline.Token;
            string operation = request["operation"]!.GetValue<string>();
            if (operation is not ("inventory" or "types" or "methods" or "decompile" or "assembly" or "references" or "member_refs" or "resources" or "trace" or "artifact")) throw new ArgumentException("Unsupported operation");
            string path = request["path"]!.GetValue<string>();
            if (!Path.IsPathFullyQualified(path)) throw new ArgumentException("Absolute input path required");
            byte[] bytes;
            using (var file = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read))
            {
                if (file.Length < 1 || file.Length > InputLimit) throw new ArgumentException("Input must be 1 byte to 16 MiB");
                bytes = new byte[checked((int)file.Length)];
                file.ReadExactly(bytes);
                if (file.ReadByte() != -1) throw new IOException("Input grew during snapshot");
            }
            string hash = Convert.ToHexStringLower(SHA256.HashData(bytes));
            if (request["sha256"]?.GetValue<string>() != hash) throw new ArgumentException("Artifact hash mismatch");
            response["artifact_sha256"] = hash;
            if(operation=="artifact") {
                ArtifactReader.Read(bytes,request,response,limit,offset,cancellation);
                string result=response.ToJsonString();if(Encoding.UTF8.GetByteCount(result)+1>outputLimit)throw new OutputLimitException();
                Console.WriteLine(result);return response["status"]!.GetValue<string>()=="completed"?0:1;
            }
            if(operation=="trace") {
                TraceReader.Read(bytes,response,limit,offset,cancellation);
                string traceResult=response.ToJsonString();
                if(Encoding.UTF8.GetByteCount(traceResult)+1>outputLimit)throw new ArgumentException("Trace response exceeds output budget; reduce limit");
                Console.WriteLine(traceResult);return response["status"]!.GetValue<string>()=="completed"?0:3;
            }
            using var stream = new MemoryStream(bytes, writable: false);
            using var module = new ManagedPE(path, stream, PEStreamOptions.PrefetchEntireImage);
            var metadata = module.Metadata;
            if (module.CorHeader == null) throw new BadImageFormatException("No managed CLR header");
            response["operation"] = operation;
            response["status"] = "completed";
            response["module_mvid"] = metadata.GetGuid(metadata.GetModuleDefinition().Mvid).ToString();
            response["machine"] = module.Reader.PEHeaders.CoffHeader.Machine.ToString();
            response["pe_magic"] = module.Reader.PEHeaders.PEHeader?.Magic.ToString();
            response["clr_flags"] = module.CorHeader.Flags.ToString();
            response["metadata_version"] = Short(metadata.MetadataVersion);
            response["type_count"] = metadata.TypeDefinitions.Count;
            response["method_count"] = metadata.MethodDefinitions.Count;
            if(request.ContainsKey("dependencies")&&request["dependencies"] is not JsonArray)throw new ArgumentException("Dependencies must be an array");
            using var resolver = new ImportedResolver(request["dependencies"] as JsonArray);
            response["imported_dependencies"]=resolver.Inventory();
            response["dependency_resolution"] = request["dependencies"] is JsonArray { Count: >0 } ? "explicit_imports_only" : "disabled";
            if (operation is "references" or "resources" or "member_refs") {
                var rows=new JsonArray();response[operation]=rows;
                var memberDecompiler=operation=="member_refs"?new CSharpDecompiler(module,resolver,new DecompilerSettings {ThrowOnAssemblyResolveErrors=false,UseDebugSymbols=false}) {CancellationToken=cancellation}:null;
                int total=operation=="references"?metadata.AssemblyReferences.Count:operation=="member_refs"?metadata.MemberReferences.Count:metadata.ManifestResources.Count;
                int cursor=Math.Min(offset,total);
                while(cursor<total&&rows.Count<limit) {
                    cancellation.ThrowIfCancellationRequested();JsonObject item;
                    if(operation=="member_refs") {
                        var h=MetadataTokens.MemberReferenceHandle(cursor+1);
                        var entity=((MetadataModule)memberDecompiler!.TypeSystem.MainModule).ResolveEntity(h,default(GenericContext));
                        var destination=entity?.ParentModule?.MetadataFile;
                        var targetHash=destination==module?hash:resolver.Hash(destination);
                        var token=entity?.MetadataToken??default;
                        bool resolved=targetHash!=null&&!token.IsNil;
                        item=new JsonObject {["token"]=$"0x{MetadataTokens.GetToken(h):x8}",["location"]=Location(h),["name"]=Short(metadata.GetString(metadata.GetMemberReference(h).Name)),["resolution"]=resolved?"native_metadata_resolution":"unresolved",["target_artifact_sha256"]=resolved?targetHash:null,["target_token"]=resolved?$"0x{MetadataTokens.GetToken(token):x8}":null};
                    } else if(operation=="references") {
                        var h=MetadataTokens.AssemblyReferenceHandle(cursor+1);var a=metadata.GetAssemblyReference(h);
                        var key=metadata.GetBlobBytes(a.PublicKeyOrToken);
                        if((a.Flags & System.Reflection.AssemblyFlags.PublicKey)!=0&&key.Length!=0)key=SHA1.HashData(key)[^8..].Reverse().ToArray();
                        var identity=ImportedResolver.Identity(metadata.GetString(a.Name),a.Version,metadata.GetString(a.Culture),key);
                        var resolved=resolver.ResolveIdentity(identity);
                        item=new JsonObject {["token"]=$"0x{MetadataTokens.GetToken(h):x8}",["location"]=Location(h),["name"]=Short(identity),["target_artifact_sha256"]=resolved,["resolution"]=resolved==null?"unresolved":"exact_assembly_identity"};
                    } else {
                        var h=MetadataTokens.ManifestResourceHandle(cursor+1);var resource=metadata.GetManifestResource(h);
                        item=new JsonObject {["token"]=$"0x{MetadataTokens.GetToken(h):x8}",["location"]=Location(h),["name"]=Short(metadata.GetString(resource.Name)),["embedded"]=resource.Implementation.IsNil,["resource_offset"]=resource.Offset,["extraction_status"]="not_requested"};
                        if(resource.Implementation.IsNil) {
                            long rva=(long)module.CorHeader.ResourcesDirectory.RelativeVirtualAddress+resource.Offset;
                            var section=module.Reader.PEHeaders.SectionHeaders.FirstOrDefault(s=>rva>=s.VirtualAddress&&rva-s.VirtualAddress<s.SizeOfRawData);
                            long start=(long)section.PointerToRawData+rva-section.VirtualAddress;
                            if(section.SizeOfRawData==0||start<0||start>bytes.Length-4)throw new BadImageFormatException("Resource length outside artifact");
                            int size=System.Buffers.Binary.BinaryPrimitives.ReadInt32LittleEndian(bytes.AsSpan((int)start,4));
                            if(size<0||size>bytes.Length-start-4||resource.Offset+4L+size>module.CorHeader.ResourcesDirectory.Size||size+4L>section.SizeOfRawData-(rva-section.VirtualAddress))throw new BadImageFormatException("Resource bytes outside directory");
                            item["file_offset"]=start+4;item["size"]=size;
                            item["sha256"]=Convert.ToHexStringLower(SHA256.HashData(bytes.AsSpan((int)start+4,size)));
                            item["extraction_status"]="file_range_identified; use scoped artifact derivation";
                        }
                    }
                    rows.Add(item);
                    if(Encoding.UTF8.GetByteCount(response.ToJsonString())>outputLimit-1024){rows.RemoveAt(rows.Count-1);response["status"]="partial";break;}cursor++;
                }
                response["next_offset"]=cursor<total?cursor:null;response["collection_complete"]=cursor>=total;
            }
            else if (operation == "inventory")
            {
                response["assembly_name"] = metadata.IsAssembly ? Short(metadata.GetString(metadata.GetAssemblyDefinition().Name)) : null;
                response["assembly_reference_count"] = metadata.AssemblyReferences.Count;
            }
            else if (operation is "types" or "methods")
            {
                var items = new JsonArray();
                string collection = operation;
                response[collection] = items;
                int total = operation == "types" ? metadata.TypeDefinitions.Count : metadata.MethodDefinitions.Count;
                int cursor = Math.Min(offset, total);
                while (cursor < total && items.Count < limit)
                {
                    cancellation.ThrowIfCancellationRequested();
                    JsonObject item;
                    if (operation == "methods") item = Method(metadata, MetadataTokens.MethodDefinitionHandle(cursor + 1));
                    else
                    {
                        var handle = MetadataTokens.TypeDefinitionHandle(cursor + 1);
                        var type = metadata.GetTypeDefinition(handle);
                        item = new JsonObject { ["token"] = $"0x{MetadataTokens.GetToken(handle):x8}",
                            ["name"] = Short(metadata.GetString(type.Name)), ["namespace"] = Short(metadata.GetString(type.Namespace)),
                            ["name_truncated"] = metadata.GetString(type.Name).Length > 512,
                            ["namespace_truncated"] = metadata.GetString(type.Namespace).Length > 512,
                            ["location"] = Location(handle), ["method_count"] = type.GetMethods().Count };
                    }
                    items.Add(item);
                    if (Encoding.UTF8.GetByteCount(response.ToJsonString()) > outputLimit - 1024)
                    {
                        items.RemoveAt(items.Count - 1);
                        response["status"] = "partial";
                        response["diagnostic"] = "Output budget exhausted";
                        break;
                    }
                    cursor++;
                }
                response["offset"] = offset;
                response["next_offset"] = cursor < total ? cursor : null;
                response["collection_complete"] = cursor >= total;
            }
            else
            {
                string tokenText = request["token"]?.GetValue<string>() ?? throw new ArgumentException("MethodDef token required");
                if (!tokenText.StartsWith("0x", StringComparison.Ordinal) || !int.TryParse(tokenText.AsSpan(2), NumberStyles.AllowHexSpecifier, CultureInfo.InvariantCulture, out int token)
                    || (token & unchecked((int)0xff000000)) != 0x06000000 || (token & 0xffffff) < 1 || (token & 0xffffff) > metadata.MethodDefinitions.Count)
                    throw new ArgumentException("Valid MethodDef token required");
                var handle = MetadataTokens.MethodDefinitionHandle(token & 0xffffff);
                var method = metadata.GetMethodDefinition(handle);
                response["method"] = Method(metadata, handle);
                if(request["pdb"] is JsonObject pdb)response["original_source_mapping"]=PdbMapping.Read(module,token,pdb,cancellation);
                if (method.RelativeVirtualAddress != 0 && module.GetMethodBody(method.RelativeVirtualAddress).GetILBytes()!.Length > 16384)
                    throw new ArgumentException("Method IL exceeds 16 KiB bound");
                using var writer = new BoundedWriter(Math.Max(64, (outputLimit - 3072) / 12), cancellation);
                if (operation == "assembly")
                {
                    var mapped = new MappedOutput(writer, tokenText, (outputLimit - 3072) / 2);
                    try { new ReflectionDisassembler(mapped, cancellation).DisassembleMethod(module, handle); }
                    catch (OutputLimitException) { response["status"] = "partial"; response["diagnostic"] = "IL text output truncated"; }
                    response["assembly"] = writer.ToString();
                    response["tokens"] = mapped.References;
                    response["reference_mapping_truncated"] = mapped.Truncated;
                    response["mapping_scope"] = "ILSpy reference callbacks; UTF-16 spans in assembly text";
                    response["semantic_completeness"] = "not_evaluated";
                    if (mapped.Truncated) response["status"] = "partial";
                }
                else
                {
                    var settings = new DecompilerSettings { ThrowOnAssemblyResolveErrors = false, UseDebugSymbols = false };
                    var decompiler = new CSharpDecompiler(module, resolver, settings) { CancellationToken = cancellation };
                    try
                    {
                        var tree = decompiler.Decompile(handle);
                        tree.AcceptVisitor(new CSharpOutputVisitor(TokenWriter.CreateWriterThatSetsLocationsInAST(writer,"\t"), settings.CSharpFormattingOptions));
                        var maps=new JsonArray();response["source_il_mappings"]=maps;
                        foreach(var pair in decompiler.CreateSequencePoints(tree))foreach(var point in pair.Value) {
                            if(point.IsHidden||pair.Key.Method==null)continue;
                            if(maps.Count>=128){response["status"]="partial";response["source_mapping_truncated"]=true;break;}
                            maps.Add(new JsonObject {["method_token"]=$"0x{MetadataTokens.GetToken(pair.Key.Method.MetadataToken):x8}",["il_start"]=point.Offset,["il_end"]=point.EndOffset,["start_line"]=point.StartLine,["start_column"]=point.StartColumn,["end_line"]=point.EndLine,["end_column"]=point.EndColumn});
                        }
                    }
                    catch (OutputLimitException) { response["status"] = "partial"; response["diagnostic"] = "Pseudocode output truncated"; }
                    response["pseudocode"] = writer.ToString();
                    response["unresolved_reference_requests"] = resolver.RequestCount;
                    response["resolved_reference_requests"] = resolver.ResolvedCount;
                    response["semantic_completeness"] = "partial";
                    if (resolver.RequestCount != 0) response["status"] = "partial";
                    response["mapping_scope"] = "ILSpy generated C# sequence points; 1-based UTF-16 line/columns and half-open IL intervals, not original source";
                }
            }
            cancellation.ThrowIfCancellationRequested();
        }
        catch (OperationCanceledException) { response["status"] = "timeout"; response["diagnostic"] = "Worker wall budget exceeded"; }
        catch (OutputLimitException) { response["status"] = "partial"; response["diagnostic"] = "Worker output budget exceeded; reduce page size"; }
        catch (Exception error) { response["status"] = "failed"; response["diagnostic"] = Short(error.GetType().Name + ": " + error.Message); }
        string serialized = response.ToJsonString();
        if (Encoding.UTF8.GetByteCount(serialized) + 1 > outputLimit)
        {
            response = new JsonObject { ["backend"] = "ilspy", ["status"] = "partial", ["diagnostic"] = "Response exceeded output budget", ["target_executed"] = false, ["artifact_sha256"] = response["artifact_sha256"]?.DeepClone() };
            serialized = response.ToJsonString();
        }
        Console.WriteLine(serialized);
        return response["status"]!.GetValue<string>() switch { "completed" => 0, "partial" => 3, _ => 1 };
    }
}

internal sealed class NoAssemblyResolver : IAssemblyResolver
{
    public int RequestCount { get; private set; }
    public MetadataFile? Resolve(IAssemblyReference reference) { RequestCount++; return null; }
    public MetadataFile? ResolveModule(MetadataFile mainModule, string moduleName) { RequestCount++; return null; }
    public Task<MetadataFile?> ResolveAsync(IAssemblyReference reference) => Task.FromResult(Resolve(reference));
    public Task<MetadataFile?> ResolveModuleAsync(MetadataFile mainModule, string moduleName) => Task.FromResult(ResolveModule(mainModule, moduleName));
}
internal sealed class OutputLimitException : Exception;
internal sealed class BoundedWriter(int limit, CancellationToken cancellation) : TextWriter
{
    private readonly StringBuilder buffer = new();
    public int Length => buffer.Length;
    public override Encoding Encoding => Encoding.UTF8;
    public override void Write(char value)
    {
        cancellation.ThrowIfCancellationRequested();
        if (buffer.Length >= limit) throw new OutputLimitException();
        buffer.Append(value);
    }
    public override void Write(string? value) { if (value != null) foreach (char character in value) Write(character); }
    public override string ToString() => buffer.ToString();
}

// Preserve upstream disassembler reference callbacks, not a second IL decoder.
internal sealed class MappedOutput(BoundedWriter writer, string methodToken, int mappingBudget) : ITextOutput
{
    private readonly ITextOutput output = new PlainTextOutput(writer);
    private int bytes;
    public JsonArray References { get; } = new();
    public bool Truncated { get; private set; }
    public string IndentationString { get => output.IndentationString; set => output.IndentationString = value; }
    public void Indent() => output.Indent();
    public void Unindent() => output.Unindent();
    public void Write(char value) => output.Write(value);
    public void Write(string text) => output.Write(text);
    public void WriteLine() => output.WriteLine();
    public void MarkFoldStart(string text = "...", bool collapsed = false, bool definition = false) => output.MarkFoldStart(text, collapsed, definition);
    public void MarkDefinitionStart() => output.MarkDefinitionStart();
    public void MarkFoldEnd() => output.MarkFoldEnd();
    public void WriteReference(OpCodeInfo opCode, bool omitSuffix = false) => output.WriteReference(opCode, omitSuffix);
    public void WriteReference(IType type, string text, bool isDefinition = false) => output.WriteReference(type, text, isDefinition);
    public void WriteReference(IMember member, string text, bool isDefinition = false) => output.WriteReference(member, text, isDefinition);
    private void Reference(string text, string kind, string space, string address, bool definition)
    {
        var record = new JsonObject { ["kind"] = kind, ["text"] = text.Length <= 512 ? text : text[..512],
            ["text_truncated"] = text.Length > 512, ["start_utf16"] = writer.Length - text.Length,
            ["end_utf16"] = writer.Length, ["is_definition"] = definition,
            ["location"] = new JsonObject { ["address_space"] = space, ["address"] = address } };
        int size = Encoding.UTF8.GetByteCount(record.ToJsonString()) + 1;
        if (References.Count >= 128 || bytes + size > mappingBudget) { Truncated = true; return; }
        bytes += size;
        References.Add(record);
    }
    public void WriteReference(MetadataFile module, Handle handle, string text, string protocol = "decompile", bool isDefinition = false)
    {
        output.WriteReference(module, handle, text, protocol, isDefinition);
        if (!handle.IsNil) Reference(text, "metadata_reference", "managed_metadata", $"0x{MetadataTokens.GetToken(handle):x8}", isDefinition);
    }
    public void WriteLocalReference(string text, object reference, bool isDefinition = false, bool isHoverOnly = false)
    {
        output.WriteLocalReference(text, reference, isDefinition, isHoverOnly);
        if (reference is int offset && offset >= 0)
            Reference(text, "il_offset_reference", "managed_il:" + methodToken.ToLowerInvariant(), $"0x{offset:x}", isDefinition);
    }
}
