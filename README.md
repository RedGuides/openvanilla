# Open Vanilla

Open Vanilla is a compilation of multi-boxing software for EverQuest, nearly all based on [MacroQuest](https://github.com/macroquest/macroquest) with plugins and effort from the [RedGuides community](https://www.redguides.com). 

### Not a gnome? ⚙️
The supported version [Very Vanilla🍦](https://www.redguides.com/community/) for contributors and subscribers is ready to use immediately. If you're here to tinker, read on!

## How To Build

### Prerequisites

* [Visual Studio 2022 Community](https://visualstudio.microsoft.com/downloads/)
* [Git for Windows](https://git-scm.com/)

### Check out the latest source code

Create the checkout. This will create the subfolder **openvanilla** that contains a copy of the project.

```
git clone https://github.com/RedGuides/openvanilla.git
cd openvanilla
```

Make sure that submodules are initialized. Move (cd) to the newly created **openvanilla** folder before executing this command.  If you have run this step already, you can skip it
```
git submodule init
```

Update the submodules to the correct version. Ensure you are in the newly created **openvanilla** folder before executing this command.
```
git submodule update
```

### Updating an existing checkout

MacroQuest is updated often, especially after a patch. Make sure before you build that you have the latest source code for MacroQuest and all of its dependencies.

If you already have the source, it is a good idea to make sure that you pull all the latest changes.
```
git pull --rebase
```

Update submodules. This ensures that dependencies have the latest code.
```
git submodule update
```

At this point, the source should be ready to compile. Proceed to building.

### Building for Test or Emulator
The only difference between builds is the `eqlib` submodule. The `master` branch pins `eqlib` to **Live**. To build a different client, point `eqlib` at the matching branch before building:


For **EverQuest Test**:
```
git -C src/eqlib checkout test
```

For **EverQuest RoF2 (Emulator)**:
```
git -C src/eqlib checkout emu-rof2
```

To go back to **Live**:
```
git -C src/eqlib checkout live
```

> [!INFO]
> `git submodule update` will reset `eqlib` back to Live. Re-run your client's command above to fix.

> [!NOTE]
> RoF2 (Emulator) builds use the `Win32` platform instead of `x64` in the Build Steps below.

### Build Steps

1. Open the `src\MacroQuest.sln` file.
1. Select the `Release` and `(x64)` configuration from the drop-down menu near the top of the window.
1. Since the project moved to 64-bit, ensure all project configurations are set to `(x64)` in the **Solution Macroquest** Property Pages.  From the Visual Studio main menu, select **Build** then **Configuration Manager** then ensure the Platform column for each project is set to `(x64)`.
1. Select `Build -> Build Solution` from the menu.

The built files will be placed in `build/bin/Release`. To start MacroQuest, run `MacroQuest.exe`. This will launch the application to the tray, and install MacroQuest into any running EverQuest processes.

### Adding Your Own Plugins

_NOTE:_ If you have any custom plugins you want to build, put the sources for them in the `plugins` folder, for example:
`plugins/MQ2Foo/MQ2Foo.cpp`. Do not put them in src/plugins - this path is reserved for the MacroQuest developers.

You can create new plugins from template using the `mkplugin.exe` tool located in the `plugins` folder.

To add any existing personal plugins to the solution:
1. Right click the solution in solution explorer and click `Add -> Add Existing Project...`.
1. Select your .vcxproj file.
1. Repeat as necessary

## Directory Structure

Folder Name | Purpose
------------|-------------
build       | Build artifacts. This is where you can find the output when you compile MacroQuest and your plugins.
contrib     | Third-Party source code.
data        | Additional non-source code files used by MacroQuest.
extras      | Optional files that aren't required but may be useful. This includes sources for plugins that are no longer maintained.
include     | Public header files that are used for building MacroQuest and plugins.
plugins     | This folder is reserved for you to add your own personal plugins.
src         | The source code for MacroQuest and its core plugins.
tools       | Source code and additional tools that are used for MacroQuest development, but not part of the main project.
