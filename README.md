# GadgetHunter

A simple tool to help find `jmp` gadgets for use in call stack spoofing. It will only return those that have a `call` instruction before the gadget.

## Usage

Give it a directory to scan (such as System32) and it will process every DLL.

```text
> .\GadgetHunter.exe C:\Windows\System32

|-> C:\Windows\System32\archiveint.dll
|--> Found 1 gadget(s)
|---> jmp qword ptr [rbx] @ 0x180108B28 - call @ 0x180108B23

|-> C:\Windows\System32\AuthFWSnapin.dll
|--> Found 6 gadget(s)
|---> jmp qword ptr [rdi] @ 0x101D503B - call @ 0x101D5036
|---> jmp qword ptr [rdi] @ 0x101D523B - call @ 0x101D5236
|---> jmp qword ptr [rbx] @ 0x10234218 - call @ 0x10234213
|---> jmp qword ptr [rdi] @ 0x10454CDB - call @ 0x10454CD6
|---> jmp qword ptr [rdi] @ 0x10454EDB - call @ 0x10454ED6
|---> jmp qword ptr [rbx] @ 0x104B3DBB - call @ 0x104B3DB6
```