# Open Vanilla

Open Vanilla is a compilation of multi-boxing software for EverQuest. It's based on [MacroQuest](https://gitlab.com/macroquest/), with plugins and ❤️ from the [RedGuides community](https://www.redguides.com). 
### Not a gnome? ⚙️
The pre-built and supported version [Very Vanilla🍦](https://www.redguides.com/community/resources/redguides-launcher.1255/) is available for contributors and subscribers. If you'd rather tinker, read on!

---
## Build

### Prerequisites

* [Visual Studio 2019 Community](https://visualstudio.microsoft.com/downloads/)
* [Git for Windows](https://git-scm.com/)

### Prepare for build

1) Clone the repository with this line, (newest version of Git required)

```
git clone --recurse-submodules -j8 https://gitlab.com/redguides/openvanilla.git
```

2) Run `MQ2Auth.exe` to generate the authorization file for your computer. Personal builds are machine-locked; they can only be run on the machine that built them. 

### Build Steps

1. Open the `OpenVanilla.sln` file in /src
1. Select the `Release` configuration from the drop-down menu near the top of the window
1. Select `Build -> Build Solution` from the menu.

The built files will be placed in `build/bin/Release`. To start MacroQuest, run `MacroQuest.exe`. This will launch the application to the tray, and inject MacroQuest into any running EverQuest processes. 

You're ready to play! If you're new to multi-boxing, watch our [video series](https://www.redguides.com/community/resources/multiboxing-everquest-the-red-guide-videos.1603/).

### Updating an existing checkout

Updates are frequent, and are required after an EverQuest patch. Before you build, grab the latest source code.

If you already have the source, it's a good idea to make sure that you pull all the latest changes.
```
git pull --rebase
```

Update submodules. This ensures that dependencies have the latest code.
```
git submodule update
```
You're now ready to follow the build steps again.

### Adding Your Own Plugins

_NOTE:_ If you have any custom plugins you want to build, put the sources for them in the `plugins` folder, for example:
`plugins/MQ2Foo/MQ2Foo.cpp`. Do not put them in src/plugins - this path is reserved for the MacroQuest developers

To add any personal plugins to the solution:
1. Right clicking the solution in solution explorer and clicking `Add -> Add Existing Project...`.
1. Select your .vcxproj file.
1. Repeat as necessary

## Directory Structure

Folder Name | Purpose
------------|-------------
build       | Build artifacts. This is where you can find the output when you compile MacroQuest and your plugins.
contrib     | Third-Party source code.
data        | Additional non-source code files used by MacroQuest.
docs        | Documentation
extras      | Optional files that aren't required but may be useful. This includes sources for plugins that are no longer maintained.
include     | Public header files that are used for building MacroQuest and plugins.
plugins     | This folder is reserved for you to add your own personal plugins.
src         | The source code for MacroQuest and its core plugins.
tools       | Source code and additional tools that are used for MacroQuest development, but not part of the main project.

### Additional files of interest

**MQ2Auth.exe** Generates MQ2Auth.h, run this first before building the solution

**plugins/mkplugin.exe** Generates a new plugin from the template. Use this when creating a new plugin, or when converting an existing plugin from legacy MacroQuest.
