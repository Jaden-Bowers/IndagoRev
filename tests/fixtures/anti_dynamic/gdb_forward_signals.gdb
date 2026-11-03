# Forward raise()/tgkill() traps (Linux SI_TKILL=-6), not loader/debugger traps.
handle SIGUSR1 nostop noprint pass
catch signal SIGTRAP
condition $bpnum $_siginfo.si_code == -6
commands
  silent
  signal SIGTRAP
end
run
