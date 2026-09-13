using System.Reflection.Metadata;
using System.Reflection.Metadata.Ecma335;
using System.Reflection.PortableExecutable;
using System.Security.Cryptography;
using System.Text.Json.Nodes;
internal static class PdbMapping {
    public static JsonObject Read(ICSharpCode.Decompiler.Metadata.PEFile module,int token,JsonObject request,CancellationToken cancel) {
        string path=request["path"]!.GetValue<string>(),hash=request["sha256"]!.GetValue<string>();
        if(!Path.IsPathFullyQualified(path))throw new ArgumentException("Absolute imported PDB snapshot required");
        using var stream=new FileStream(path,FileMode.Open,FileAccess.Read,FileShare.Read);
        if(stream.Length>16777216)throw new ArgumentException("PDB exceeds 16 MiB");
        byte[] bytes=new byte[(int)stream.Length];stream.ReadExactly(bytes);
        if(Convert.ToHexStringLower(SHA256.HashData(bytes))!=hash)throw new ArgumentException("PDB hash mismatch");
        using var provider=MetadataReaderProvider.FromPortablePdbStream(new MemoryStream(bytes,false));
        var metadata=provider.GetMetadataReader();var id=metadata.DebugMetadataHeader!.Id;
        var guid=new Guid(id.AsSpan(0,16));var stamp=System.Buffers.Binary.BinaryPrimitives.ReadUInt32LittleEndian(id.AsSpan(16,4));
        bool matched=false;
        foreach(var entry in module.Reader.ReadDebugDirectory())if(entry.Type==DebugDirectoryEntryType.CodeView) {
            var cv=module.Reader.ReadCodeViewDebugDirectoryData(entry);
            if(cv.Guid==guid&&entry.Stamp==stamp&&cv.Age==1)matched=true;
        }
        if(!matched)throw new ArgumentException("Portable PDB does not match PE debug identity");
        var rows=new JsonArray();var method=metadata.GetMethodDebugInformation(MetadataTokens.MethodDebugInformationHandle(token&0xffffff));
        bool truncated=false;
        foreach(var point in method.GetSequencePoints()) {
            cancel.ThrowIfCancellationRequested();if(point.IsHidden)continue;
            if(rows.Count>=128){truncated=true;break;}
            var document=metadata.GetDocument(point.Document.IsNil?method.Document:point.Document);
            var name=metadata.GetString(document.Name);
            rows.Add(new JsonObject {["il_offset"]=point.Offset,["start_line"]=point.StartLine,["start_column"]=point.StartColumn,["end_line"]=point.EndLine,["end_column"]=point.EndColumn,
              ["document"]=name.Length>512?name[..512]:name,["document_hash_algorithm"]=metadata.GetGuid(document.HashAlgorithm).ToString(),["document_hash"]=Convert.ToHexStringLower(metadata.GetBlobBytes(document.Hash))});
        }
        return new JsonObject {["pdb_sha256"]=hash,["debug_identity_matched"]=true,["method_token"]=$"0x{token:x8}",["sequence_points"]=rows,["truncated"]=truncated,["source_files_read"]=false};
    }
}
