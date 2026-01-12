# MinGW One-Liner Compilation Commands for LowPrivsExclusionCheckASR

## For Windows with MinGW-w64 installed:

### Build both x64 and x86 in one command:
```cmd
x86_64-w64-mingw32-gcc -c -Os -Wall LowPrivsExclusionCheckASR.c -o LowPrivsExclusionCheckASR.x64.o && i686-w64-mingw32-gcc -c -Os -Wall LowPrivsExclusionCheckASR.c -o LowPrivsExclusionCheckASR.x86.o
```

### Build x64 only:
```cmd
x86_64-w64-mingw32-gcc -c -Os -Wall LowPrivsExclusionCheckASR.c -o LowPrivsExclusionCheckASR.x64.o
```

### Build x86 only:
```cmd
i686-w64-mingw32-gcc -c -Os -Wall LowPrivsExclusionCheckASR.c -o LowPrivsExclusionCheckASR.x86.o
```

---

## For PowerShell:

### Build both:
```powershell
x86_64-w64-mingw32-gcc -c -Os -Wall LowPrivsExclusionCheckASR.c -o LowPrivsExclusionCheckASR.x64.o; i686-w64-mingw32-gcc -c -Os -Wall LowPrivsExclusionCheckASR.c -o LowPrivsExclusionCheckASR.x86.o
```

### Build x64 only:
```powershell
x86_64-w64-mingw32-gcc -c -Os -Wall LowPrivsExclusionCheckASR.c -o LowPrivsExclusionCheckASR.x64.o
```

---

## Ultra-minimal (x64 only, no warnings):
```cmd
x86_64-w64-mingw32-gcc -c -Os LowPrivsExclusionCheckASR.c -o LowPrivsExclusionCheckASR.x64.o
```

---

## If MinGW is installed but not in PATH:
```cmd
C:\mingw64\bin\x86_64-w64-mingw32-gcc -c -Os -Wall LowPrivsExclusionCheckASR.c -o LowPrivsExclusionCheckASR.x64.o
```

---

## Copy-paste ready (CMD):
```
x86_64-w64-mingw32-gcc -c -Os -Wall LowPrivsExclusionCheckASR.c -o LowPrivsExclusionCheckASR.x64.o && i686-w64-mingw32-gcc -c -Os -Wall LowPrivsExclusionCheckASR.c -o LowPrivsExclusionCheckASR.x86.o && echo Build complete! && dir *.o
```

## Copy-paste ready (PowerShell):
```
x86_64-w64-mingw32-gcc -c -Os -Wall LowPrivsExclusionCheckASR.c -o LowPrivsExclusionCheckASR.x64.o; i686-w64-mingw32-gcc -c -Os -Wall LowPrivsExclusionCheckASR.c -o LowPrivsExclusionCheckASR.x86.o; Write-Host "Build complete!"; dir *.o
```

---

## Visual Studio (x64 Native Tools Command Prompt):
```cmd
cl.exe /c /GS- /nologo /Oi /W3 LowPrivsExclusionCheckASR.c && ren LowPrivsExclusionCheckASR.obj LowPrivsExclusionCheckASR.x64.o
```
