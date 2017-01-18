<p align="center"><img src ="images/header.png" /></p>

**xAnalyzer** is a plugin for the x86/x64 x64dbg debugger by @mrexodia. This plugin is based on [APIInfo Plugin](https://github.com/mrfearless/APIInfo-Plugin-x86) by @mrfearless, although some improvements and additions have been made. **xAnalyzer** is capable of doing various types of analysis over the static code of the debugged application to give more extra information to the user. This plugin is going to make an extensive API functions call detections to add functions definitions, arguments and data types as well as any other complementary information, something close at what you get with OllyDbg analysis engine, in order to make it even more comprehensible to the user just before starting the debuggin task.

## Table Of Contents

- [Features](#features)
- [Installation](#installation)
- [Configuration](#configuration)
- [Usage](#usage)
- [API Definition Files](#api-definition-files)
- [Known issues and limitations](#known-issues-and-limitations)
- [To-Do Long-Term](#to-do-long-term)
- [Contributing Guidelines](#contributing-guidelines)

## Features
Some of the main features and improvements include:

- Extended function calls analysis (defined/undefined) 

- Defined and/or generic arguments, data types and additional debugging info.

- Automatic loops detection.

- User maintained definition files

Before xAnalyzer
<p align="center"><img width=80% height=80% src ="images/before_analysis.png" /></p>

After xAnalyzer
<p align="center"><img width=80% height=80% src ="images/after_analysis.png" /></p>

## Installation
1. Download the latest version of [x64dbg](https://github.com/x64dbg/x64dbg/releases/tag/snapshot)

2. Copy *xAnalyzer.dp32/xAnalyzer.dp64* files and *apis_def* folder to x32/x64 respective plugins directories of x64dbg

3. Look under the "*Plugins*" menu in the main x64dbg window or in the secondary menu in the Disasm window as well for an "*xAnalyzer*" entry

## Configuration
xAnalyzer has some options to choose from in order to personalize even more the experience with it, to use it just when you need it and the way you wan it. The plugin options are as follows:

- **Automatic Analysis**: When this option is ON, the plugin is going to launch a full automatic analysis over the executable code every time it reaches the entry point when loading on the debugger. By using this option you get the more closer OllyDbg initial analysis behavior on x64dbg.

- **Extended Analysis**: This option is going to force xAnalyzer to make an extended analysis over the entire code section of the debugged executable. 
*WARNING!!! By enabling this option the analysis process may take much more time and resources to complete, also larges amount of RAM memory might be used by x64dbg depending on the size of the section and the amount of extra data added to the debugged executable static disassembly*

- **Analyze Undefined Functions**: By selecting this option xAnalyzer will use generic analysis and argument types for all of those API Calls/Functions that are not defined in the api definition files and also calls like:
````
CALL {REGISTER}
CALL {REGISTER + DISPLACEMENT}
CALL {DYNAMIC_POINTER}
````

## Usage
xAnalyzer has some commands and menu options to choose from when working with an executable:

### Analyze Selection
By making a selection of several instructions in the disassembly windows of x64dbg and selecting this menu, a fast analysis will be made over the selected lines. You can also use the hotkeys *Ctrl+X* for launching this option.

<p align="center"><img width=80% height=80% src ="images/selection_analysis.gif" /></p>

### Analyze Function
If you are in the middle of some function you could use this menu entry to analyze that entire function and only that function. Taking your single selected instruction as a reference xAnalyzer will process from there all the lines inside a block of code. You could also use the hotkeys *Ctrl+Shift+X* for launching this type of analysis

<p align="center"><img width=80% height=80% src ="images/function_analysis.gif" /></p>

### Analyze Executable
This command it's going to launch a full analysis over the entire executable. This feature takes the **Extended Analysis** option into consideration for the depth of analysis to be used.

### Remove Analysis Menus
In these cases, all of these menus are going to make the opposite of what the previous commands did. In case you want to get rid of the analysis extra information in some parts of the code or in the entire executable if wished.

## API Definition Files
xAnalyzer has an expandable system of API definition files, these files are present in the folder *api_def* which should contain all the files with a .ini structure and with the norm of:

- "*filename*": This is the name of the module on which the API function is located in.

- "*.api*" extension: Specifies that it is a definition file, no other extension will be recognized (kernel32.api, shell32.api, etc)

All these ini files contain important information for the plugin such as, the functions prototypes, argument types, etc. All of this information is used by xAnalyzer in order the set the extra information on the static code. A single entry in any of these files would be like:
````
[MessageBoxA]
1=HWND hWnd
2=LPCSTR lpText
3=LPCSTR lpCaption
4=UINT uType
ParamCount=4
@=MessageBoxA(HWND hWnd, LPCSTR lpText, LPCSTR lpCaption, UINT uType);
````

If you find that a certain API call definition is not being detected or not detected correctly by xAnalyzer it might mean that it's not present in the definition files or that it is defined incorrectly, so in this case an addition or modification could be made to include any missing function or arguments as long as the same structure is followed it may be 100% customizable.

## Known issues and limitations

- First undefined call with generic arguments in a function will not be processed, unless it's preceded by a jump, since there's no way to tell how many arguments to use without illegaly using the function prolog instructions. Only docummented calls will be processed at the begining of a function or an undefined function that has been presided by a jump.

- Some "uncommon" functions have arguments among jumps, so according to the actual desgin of the plugin (no jumps among functions arguments) these calls won't be processed, since each time a jump is found the instructions in the stack are cleaned.

- Nested calls will work correctly only when:
  a- Inner call is defined
  b- If inner undefined call takes no more arguments of the stack than the arguments needed by the outter call

- It only detects loops inside functions (function boundaries Prologs/RETs). If a function contains a RET in the middle of its code it will be detected as a function end and the loops stack is cleared.

- Incorrect loop detection for a section with an non-conditional jump inside it (See [#7](https://github.com/ThunderCls/xAnalyzer/issues/7))

- Nested argument lines (xAnalyzer has support for nested arguments but x64dbg at the moment doesn't)

## To-Do Long-Term

- Add entropy analysis

- Add an API's constants recognition system for each API constant argument used (MB_OK, INVALID_HANDLE_VALUE, GENERIC_READ, etc)

- Flow analysis scanning instead of linear (trace emulation)

- Case-Switch detection

## Contributing Guidelines

Contributions of all kinds are welcome, not only in the form of code but also with regards bug reports and documentation.

Please keep the following in mind:

- **Bug Reports**:  Make sure you're running the latest versions of the plugin and x64dbg, also make sure you have no other plugins loaded but xAnalyzer plugin. If the issue(s) still persist: please open a clearly documented issue with a clear title and as much information as possible in order to replicate the issue and give it solution.

Thanks for using xAnalyzer plugin...and Happy Reversing to All!
