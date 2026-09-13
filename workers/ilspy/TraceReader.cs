using System.Text.Json.Nodes;
using Microsoft.Diagnostics.Tracing;

internal static class TraceReader {
    public static void Read(byte[] bytes,JsonObject response,int limit,int offset,CancellationToken cancellation) {
        var events=new JsonArray();response["events"]=events;int seen=0,skipped=0;
        var counts=new Dictionary<string,int>();
        using var source=new EventPipeEventSource(new MemoryStream(bytes,false));
        source.Clr.All+=e=>{
            cancellation.ThrowIfCancellationRequested();
            string name=e.EventName;
            if(!name.Contains("Method")&&!name.Contains("Assembly")&&!name.Contains("Module")&&!name.Contains("Exception"))return;
            seen++;if(seen<=offset)return;
            string family=name.Contains("Exception")?"exception":name.Contains("Module")?"module":name.Contains("Assembly")?"assembly":"method";
            counts.TryGetValue(family,out int count);
            // Reserve space for late exceptions and loader identities rather than
            // letting early framework JIT noise consume the entire response.
            if(events.Count>=limit||count>=Math.Max(1,limit/4)){skipped++;return;}
            var payload=new JsonObject();
            foreach(var key in e.PayloadNames.Take(32)) {
                var value=e.PayloadByName(key);var text=value?.ToString()??"";
                payload[key]=text.Length>512?text[..512]:text;
            }
            events.Add(new JsonObject {["kind"]="managed_"+family,["native_event"]=name,["event_index"]=seen-1,
                ["pid"]=e.ProcessID,["thread_id"]=e.ThreadID,["timestamp_ms"]=e.TimeStampRelativeMSec,["payload"]=payload});
            counts[family]=count+1;
        };
        source.Process();response["matching_events"]=seen;response["omitted_events"]=skipped;
        response["events_lost"]=source.EventsLost;response["status"]=skipped>0||source.EventsLost>0?"partial":"completed";
        response["collection_complete"]=skipped==0&&source.EventsLost==0;
        response["mapping_scope"]="native ModuleID/AssemblyID/MethodToken relationships scoped to this trace; paths/names are observations, not verified artifact hashes";
        response["target_executed"]=false;response["producer"]="Microsoft TraceEvent EventPipe parser";
    }
}
