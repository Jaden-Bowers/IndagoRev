IndagoRev Desktop

Double-click IndagoRev.exe, then click Choose folder and select the directory
containing your program or source files. Runtime paths are found beside the app;
no terminal, npm installation, or manually entered paths are needed to launch.

Keep this entire folder together. IndagoRev.exe is the GUI; indago.exe is the
native analysis worker. runtime/ contains Node and agent/ contains pinned Pi
dependencies. Do not move just the GUI executable out of the package.

Decompiler/disassembler views use the native build's Ghidra engine. It may take
time to initialize on first use. Original target execution is not required.
Selecting a new binary asks before analysis. Confirming runs standard analysis
and decompiles all discovered functions into continuous listings. Click a line
to synchronize panes, or Shift-click a range and attach it with AI reference.
Unmapped instructions and incomplete decompilations remain explicit.

Chat defaults to LM Studio on http://127.0.0.1:1234/v1. Run your local model
server first, or choose another OpenAI-compatible provider in Agent Settings.
The package does not contain model weights, LM Studio, Python, or every optional
host analysis tool. Remote providers receive the context the agent sends them.
Set API-key environment variables before launching when using a remote provider.
Context capacity is read-only and retrieved from provider metadata. For LM Studio
it reflects the loaded instance, not the model's maximum supported context.

The agent retains host shell access: this is not a sandbox. Use trusted inputs
or a suitable lab. Investigation state is stored in .indago-desktop inside the
selected project. Keep projects outside this application folder.
You can choose a separate analysis folder before opening the project. Ghidra
cannot store its Program in dot-prefixed paths; those projects also have a
durable IndagoRev-GhidraProjects folder at the nearest clean ancestor. Keep that
folder with your investigation. Saved listings reopen without decompiling again;
artifact or annotation changes invalidate stale listings. Cancelled passes
retain completed functions.

This is a Windows x64 development package, not a cross-machine-qualified release.
Third-party licenses remain with their packages and in notices/.
