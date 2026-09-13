using System.Diagnostics;
using System.IO.Compression;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json.Nodes;
using OpenMcdf;
using UglyToad.PdfPig;
internal static class ArtifactReader {
    static string Short(string s)=>s.Length>4096?s[..4096]:s;
    public static void Read(byte[] bytes,JsonObject request,JsonObject response,int limit,int offset,CancellationToken cancellation) {
        string? selected=request["entry"]?.GetValue<string>();
        response["operation"]="artifact";response["status"]="completed";response["target_executed"]=false;
        var rows=new JsonArray();response["items"]=rows;int count=0;
        void Row(JsonObject row){if(count++>=offset&&rows.Count<limit)rows.Add(row);}
        void Content(byte[] content,string identity) {
            response["content_identity"]=identity;response["content_sha256"]=Convert.ToHexStringLower(SHA256.HashData(content));response["content_size"]=content.Length;
            if(request["output_path"] is JsonValue output) {
                if(content.Length>1048576)throw new ArgumentException("Derived member exceeds 1 MiB");
                string path=output.GetValue<string>();
                if(path=="@receipt"){response["private_content_hex"]=Convert.ToHexStringLower(content);response["extracted"]=true;return;}
                if(!Path.IsPathFullyQualified(path))throw new ArgumentException("Absolute private output required");
                using var destination=new FileStream(path,FileMode.CreateNew,FileAccess.Write,FileShare.None);destination.Write(content);response["extracted"]=true;
            } else {
                int start=Math.Min(offset,content.Length),length=Math.Min(8192,content.Length-start);
                response["byte_offset"]=start;response["content_hex"]=Convert.ToHexStringLower(content.AsSpan(start,length));response["content_complete"]=start==0&&length==content.Length;
            }
        }
        bool Magic(params byte[] magic)=>bytes.AsSpan().StartsWith(magic);
        if(Magic(0x50,0x4b,3,4)) {
            response["format"]="zip";response["producer"]="System.IO.Compression";
            using var archive=new ZipArchive(new MemoryStream(bytes,false),ZipArchiveMode.Read);
            if(archive.Entries.Count>2048)throw new ArgumentException("Archive entry bound exceeded");
            var seen=new HashSet<string>();bool found=false;
            foreach(var e in archive.Entries){cancellation.ThrowIfCancellationRequested();
                if(e.FullName.Length>1024||!seen.Add(e.FullName))throw new ArgumentException("Ambiguous archive member");
                Row(new JsonObject {["name"]=e.FullName,["size"]=e.Length,["compressed_size"]=e.CompressedLength,["directory"]=e.FullName.EndsWith('/')});
                if(selected==e.FullName){if(e.Length>16777216||e.FullName.EndsWith('/'))throw new ArgumentException("Selected member bound exceeded");using var stream=e.Open();byte[] child=new byte[(int)e.Length];stream.ReadExactly(child);if(stream.ReadByte()!=-1)throw new ArgumentException("Member length mismatch");Content(child,e.FullName);found=true;}
            }if(selected!=null&&!found)throw new ArgumentException("Archive member not found");
        } else if(Magic(0xd0,0xcf,0x11,0xe0,0xa1,0xb1,0x1a,0xe1)) {
            response["format"]="ole_cfb";response["producer"]="OpenMcdf 3.3.0";bool found=false;int visited=0;
            using var root=RootStorage.Open(new MemoryStream(bytes,false),StorageModeFlags.None);
            void Walk(Storage storage,string prefix,int depth){if(depth>16)throw new ArgumentException("OLE nesting bound");foreach(var e in storage.EnumerateEntries()){
                cancellation.ThrowIfCancellationRequested();if(++visited>2048)throw new ArgumentException("OLE entry bound");string name=prefix+e.Name;
                Row(new JsonObject {["name"]=name,["size"]=e.Length,["type"]=e.Type.ToString()});
                if(e.Type==EntryType.Storage){var child=storage.OpenStorage(e.Name);Walk(child,name+"/",depth+1);}
                else if(selected==name){if(e.Length>16777216)throw new ArgumentException("OLE stream byte bound");using var stream=storage.OpenStream(e.Name);var content=new byte[(int)e.Length];stream.ReadExactly(content);Content(content,name);found=true;}
            }}Walk(root,"",0);if(selected!=null&&!found)throw new ArgumentException("OLE stream not found");
            response["macro_execution"]=false;response["semantic_scope"]="structured streams; VBA/XLM instruction semantics remain separate from stream extraction";
        } else if(Magic(0x25,0x50,0x44,0x46,0x2d)) {
            response["format"]="pdf";response["producer"]="PdfPig 0.1.16";
            using var pdf=PdfDocument.Open(bytes);response["page_count"]=pdf.NumberOfPages;
            if(selected!=null) {
                var parts=selected.Split(':');if(parts.Length!=2||!long.TryParse(parts[0],out var number)||!int.TryParse(parts[1],out var generation)||number<0||generation<0)throw new ArgumentException("PDF entry must be object:generation");
                var obj=pdf.Structure.GetObject(new UglyToad.PdfPig.Core.IndirectReference(number,generation));
                if(obj.Data is UglyToad.PdfPig.Tokens.StreamToken stream){Content(stream.Data.ToArray(),selected);response["stream_dictionary"]=Short(stream.StreamDictionary.ToString());response["stream_encoding"]="raw; apply dictionary filters before interpreting";}
                else {response["object_text"]=Short(obj.Data.ToString()??"");response["object_location"]=selected;}
            } else for(int page=offset+1;page<=pdf.NumberOfPages&&rows.Count<limit;page++){cancellation.ThrowIfCancellationRequested();var p=pdf.GetPage(page);rows.Add(new JsonObject {["page"]=page,["text"]=Short(p.Text),["text_truncated"]=p.Text.Length>4096,["location_space"]="pdf_page"});}
            var objects=new JsonArray();foreach(var reference in pdf.Structure.CrossReferenceTable.ObjectOffsets.Keys.Skip(offset).Take(limit)){cancellation.ThrowIfCancellationRequested();objects.Add(reference.ObjectNumber+":"+reference.Generation);}
            response["objects"]=objects;response["object_count"]=pdf.Structure.CrossReferenceTable.ObjectOffsets.Count;
            response["active_content_executed"]=false;count=pdf.NumberOfPages;
        } else if(Magic(0,0x61,0x73,0x6d)) {
            response["format"]="wasm";response["producer"]="WABT 1.0.41 wasm2wat";
            string tool=Path.Combine(AppContext.BaseDirectory,"tools","wabt","wasm2wat"+(OperatingSystem.IsWindows()?".exe":""));
            using var process=new Process {StartInfo=new ProcessStartInfo(tool){RedirectStandardInput=true,RedirectStandardOutput=true,RedirectStandardError=true,UseShellExecute=false,CreateNoWindow=true}};
            process.StartInfo.ArgumentList.Add("-");process.Start();
            try {
                var error=Task.Run(async()=>{var text=new StringBuilder();char[] part=new char[512];int length;while((length=await process.StandardError.ReadAsync(part,cancellation))>0){if(text.Length<4096)text.Append(part,0,Math.Min(length,4096-text.Length));}return text.ToString();},cancellation);
                var input=Task.Run(async()=>{await process.StandardInput.BaseStream.WriteAsync(bytes,cancellation);process.StandardInput.Close();},cancellation);
                using var writer=new BoundedWriter(16384,cancellation);char[] buffer=new char[512];int read;
                while((read=process.StandardOutput.Read(buffer,0,buffer.Length))>0)writer.Write(buffer,0,read);
                process.WaitForExit();input.GetAwaiter().GetResult();response["text"]=writer.ToString();response["native_exit_code"]=process.ExitCode;
                if(process.ExitCode!=0){response["status"]="failed";response["diagnostic"]=Short(error.GetAwaiter().GetResult());}
            } finally {if(!process.HasExited)process.Kill(true);}
        } else {
            response["format"]="source_or_data";response["producer"]="bounded UTF-8 source reader";
            int start=Math.Min(offset,bytes.Length),length=Math.Min(8192,bytes.Length-start);
            try{response["text"]=new UTF8Encoding(false,true).GetString(bytes,start,length);response["byte_offset"]=start;response["line_base"]=1+bytes.Take(start).Count(b=>b==10);response["text_sha256"]=Convert.ToHexStringLower(SHA256.HashData(bytes.AsSpan(start,length)));}
            catch(DecoderFallbackException){Content(bytes,"artifact");response["format"]="binary_data";}
            response["semantic_scope"]="source/data inspection and helper reconstruction; not interpreter execution";
        }
        if(count>offset+rows.Count)response["next_offset"]=offset+rows.Count;
        response["parser_memory_quota_enforced"]=false;
    }
}
