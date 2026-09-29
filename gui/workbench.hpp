#pragma once

// #pragma once prevents this header being included more than once in a source
// file. These declarations let main_macos.mm call functions whose implementations
// live in workbench.cpp; the header does not draw anything itself.

// Set the colors once when the app starts, then draw the layout each frame.
void SetWorkbenchStyle();
void DrawWorkbench();
