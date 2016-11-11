# xAnalyzer
xAnalyzer plugin for x64dbg

xAnalyzer v1 plugin by ThunderCls - 2016

Blog: http://reversec0de.wordpress.com


xAnalyzer is a plugin for the x86/x64 x64dbg debugger by @mrexodia. This plugin is based on the code by @mrfearless APIInfo-Plugin-x86 (https://github.com/mrfearless/APIInfo-Plugin-x86) although some improvements and additions have been made. xAnalyzer is capable of calling internal commands of x64dbg to make all kind of analysis and also integrates one of his own. This plugin is going to make an extensive function calls analysis to add complementary information, something close at what you get with OllyDbg.

Some of the functions and improvements are:
- Extended WINAPI calls analysis with arguments added
- Analysis of indirect calls
- Analysis of nested calls

Once the debugged application is loaded and reaches the Entrypoint, xAnalyzer is going to launch a mix of different analysis over the static code to make it even more comprehensible to the user just before starting the debuggin task.

Plugin based on: APIInfo-Plugin-x86 (https://github.com/mrfearless/APIInfo-Plugin-x86)
Special thanks to @mrfearless for releasing the API definition files.

---

Installation:
 - Copy xAnalyzer.dp32 to x32 plugins directory of x64dbg
 - Look under the "Plugins" menu in the main x64dbg window or in the secondary menu in the Disasm window as well

---

Features & Usage:
 - The plugin launches automatically, no config, no nothing. 
 - If by any means you need to re-analyze the code, you can make right clic on the disassembler window and choose the option at the end "xAnalyzer"/"Extended analysis"
 
 ---
 
Screenshots:

- Before xAnalyzer
 ![Before xAnalyzer](https://github.com/ThunderCls/xAnalyzer/blob/master/xAnalyzer/screenshots/analysis_off.PNG)
 

- After xAnalyzer
 ![After xAnalyzer](https://github.com/ThunderCls/xAnalyzer/blob/master/xAnalyzer/screenshots/analysis_on.PNG)
