#pragma once
#include "indago/airece.hpp"
namespace indago {
// A delegated cgroup bounds the entire namespace, including compiler children.
// The caller must supply its filesystem/network namespace: cgroups alone are
// resource accounting, not an access-control boundary.
inline NativeProcessResult run_resource_scope(const std::vector<std::string> &env_arguments,
                                               NativeProcessOptions options,
                                               std::uint64_t memory=805306368,
                                               unsigned processes=32,const std::string &scope_id={}) {
#ifdef __linux__
  const auto unit = scope_id.empty()?"indago-" + make_id("worker"):scope_id;
  if(unit.size()>100||unit.find_first_not_of("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-")!=std::string::npos||unit.rfind("indago-",0)!=0)throw std::runtime_error("invalid private resource scope identifier");
  std::vector<std::string> args{"--user","--quiet","--wait","--pipe",
    "--unit="+unit,"--description=Indago bounded worker","--property=MemoryMax="+std::to_string(memory),
    "--property=MemorySwapMax=0","--property=TasksMax="+std::to_string(processes),
    "--property=CPUQuota=100%","--property=RuntimeMaxSec="+std::to_string((options.wall_time_ms+999)/1000),
    "--property=KillMode=control-group","--property=OOMPolicy=kill","--","/usr/bin/env"};
  args.insert(args.end(),env_arguments.begin(),env_arguments.end());
  auto result=run_native_process("/usr/bin/systemd-run",args,options);
  NativeProcessOptions cleanup;cleanup.wall_time_ms=2000;cleanup.max_output_bytes=1024;
  if(result.exit_code!=0){
    auto reason=run_native_process("/usr/bin/systemctl",{"--user","show","--property=Result","--value",unit+".service"},cleanup);
    if(!reason.output.empty()&&result.error.size()<options.max_output_bytes){auto diagnostic=" resource_scope_result="+reason.output;result.error+=diagnostic.substr(0,options.max_output_bytes-result.error.size());}
  }
  // Stop only the unique unit owned by this invocation, including on timeout.
  auto stopped=run_native_process("/usr/bin/systemctl",{"--user","stop",unit+".service"},cleanup);
  auto state=run_native_process("/usr/bin/systemctl",{"--user","show","--property=ActiveState","--value",unit+".service"},cleanup);
  const bool terminal=state.output=="inactive\n"||state.output=="failed\n"||
    (state.exit_code!=0&&state.error.find("could not be found")!=std::string::npos);
  if(stopped.timed_out||stopped.cancelled||state.timed_out||!terminal){result.output_complete=false;result.error+="resource scope cleanup uncertain";}
  (void)run_native_process("/usr/bin/systemctl",{"--user","reset-failed",unit+".service"},cleanup);
  return result;
#else
  (void)env_arguments;(void)options;(void)memory;(void)processes;(void)scope_id;
  throw std::runtime_error("resource-scoped worker requires supported Linux user service manager");
#endif
}
inline NativeProcessResult run_readonly_parser(const fs::path &executable,
  const std::vector<std::string> &arguments,const std::vector<fs::path> &inputs,
  NativeProcessOptions options,const fs::path &payload={},std::uint64_t scratch_bytes=67108864,std::uint64_t memory_bytes=805306368) {
#ifdef __linux__
  std::vector<std::string> command{"-i","/usr/bin/bwrap","--unshare-all","--unshare-user","--disable-userns","--die-with-parent","--new-session","--cap-drop","ALL","--clearenv",
    "--setenv","HOME","/tmp","--setenv","USER","indago-worker","--setenv","LOGNAME","indago-worker","--setenv","TMPDIR","/tmp","--setenv","LC_ALL","C","--setenv","PATH","/usr/bin:/bin",
    "--ro-bind","/usr/lib","/usr/lib","--ro-bind","/lib","/lib","--ro-bind","/lib64","/lib64",
    "--proc","/proc","--dev","/dev","--size",std::to_string(scratch_bytes),"--tmpfs","/tmp"};
  if(!payload.empty())command.insert(command.end(),{"--ro-bind",fs::absolute(payload).string(),fs::absolute(payload).string()});
  const auto binary=fs::absolute(executable).string();
  command.insert(command.end(),{"--ro-bind",binary,binary});
  for(const auto &input:inputs){const auto file=fs::absolute(input).string();command.insert(command.end(),{"--ro-bind",file,file});}
  command.insert(command.end(),{"--remount-ro","/","--chdir","/tmp",binary});
  command.insert(command.end(),arguments.begin(),arguments.end());
  return run_resource_scope(command,options,memory_bytes);
#else
  (void)inputs;(void)payload;(void)scratch_bytes;options.process_memory_bytes=memory_bytes;
  return run_native_process(executable,arguments,options);
#endif
}
}
