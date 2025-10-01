using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;

namespace GadgetHunter;

internal static class Program
{
    public static void Main(string[] args)
    {
        if (args.Length != 1)
        {
            Console.WriteLine("Usage: GadgetHunter <directory>");
            return;
        }

        var dir = args[0];

        if (!Directory.Exists(dir))
        {
            Console.WriteLine("Error: Directory not found.");
            return;
        }

        var dlls = Directory.GetFiles(dir, "*.dll", SearchOption.TopDirectoryOnly);

        if (dlls.Length == 0)
        {
            Console.WriteLine("No DLLs found in directory.");
            return;
        }

        foreach (var dllPath in dlls)
        {
            try
            {
                ProcessDll(dllPath);
            }
            catch
            {
                // pokemon
            }
        }
    }

    private static void ProcessDll(string path)
    {
        var data = File.ReadAllBytes(path);

        // some sanity checks on the file
        if (data.Length < 0x100)
            return;

        if (ReadUInt16(data, 0) != 0x5A4D) // "MZ"
            return;

        var e_lfanew = ReadUInt32(data, 0x3C);

        if (e_lfanew + 4 > data.Length)
            return;

        if (ReadUInt32(data, e_lfanew) != 0x00004550) // "PE\0\0"
            return;

        var numSections = ReadUInt16(data, e_lfanew + 6);
        var optHeaderSize = ReadUInt16(data, e_lfanew + 20);
        var optHeaderOffset = e_lfanew + 24;

        if (optHeaderOffset + optHeaderSize > data.Length)
            return;

        var magic = ReadUInt16(data, optHeaderOffset);
        var is64 = magic == 0x20B;
        var imageBase = is64 ? ReadUInt64(data, optHeaderOffset + 24) : ReadUInt32(data, optHeaderOffset + 28);
        var secHdrOffset = optHeaderOffset + optHeaderSize;
        
        List<SectionInfo> sections = [];

        for (var i = 0; i < numSections; i++)
        {
            var off = secHdrOffset + (uint)(i * 40);

            if (off + 40 > data.Length)
                break;

            // get some section info
            var name = ReadAsciiString(data, off, 8);
            var virtSize = ReadUInt32(data, off + 8);
            var virtAddr = ReadUInt32(data, off + 12);
            var rawSize = ReadUInt32(data, off + 16);
            var rawPtr = ReadUInt32(data, off + 20);
            var characteristics = ReadUInt32(data, off + 36);

            sections.Add(new SectionInfo
            {
                Name = name,
                RawStart = rawPtr,
                RawSize = rawSize,
                VirtAddr = virtAddr,
                VirtSize = virtSize,
                Characteristics = characteristics
            });
        }

        // store a list of gadgets found in this file
        List<Gadget> gadgets = [];

        // only iterate over the .text section
        foreach (var sec in sections.Where(s => s.Name.Equals(".text", StringComparison.OrdinalIgnoreCase)))
        {
            var start = sec.RawStart;
            var end = start + sec.RawSize;

            if (end > data.Length)
                end = (uint)data.Length;

            for (var i = start; i + 1 < end; i++)
            {
                // jmp qword ptr [rbx]
                if (data[i] == 0xFF && data[i + 1] == 0x23)
                {
                    var gadgetRva = FileOffsetToRva(sections, i);
                    var gadgetVa = imageBase + gadgetRva;

                    if (i >= 5 && data[i - 5] == 0xE8)
                    {
                        var callRva = FileOffsetToRva(sections, i - 5);
                        var callVa = imageBase + callRva;
                    
                        gadgets.Add(new Gadget("jmp qword ptr [rbx]", gadgetVa, callVa));
                    }
                }
                
                // jmp qword ptr [rsi]
                if (data[i] == 0xFF && data[i + 1] == 0x26)
                {
                    var gadgetRva = FileOffsetToRva(sections, i);
                    var gadgetVa = imageBase + gadgetRva;

                    if (i >= 5 && data[i - 5] == 0xE8)
                    {
                        var callRva = FileOffsetToRva(sections, i - 5);
                        var callVa = imageBase + callRva;
                    
                        gadgets.Add(new Gadget("jmp qword ptr [rsi]", gadgetVa, callVa));
                    }
                }
                    
                // jmp qword ptr [rdi]
                if (data[i] == 0xFF && data[i + 1] == 0x27)
                {
                    var gadgetRva = FileOffsetToRva(sections, i);
                    var gadgetVa = imageBase + gadgetRva;

                    if (i >= 5 && data[i - 5] == 0xE8)
                    {
                        var callRva = FileOffsetToRva(sections, i - 5);
                        var callVa = imageBase + callRva;
                    
                        gadgets.Add(new Gadget("jmp qword ptr [rdi]", gadgetVa, callVa));
                    }
                }
            }
        }
        
        // print any found gadgets
        if (gadgets.Count <= 0)
            return;

        Console.WriteLine();
        Console.WriteLine($"|-> {path}");
        Console.WriteLine($"|--> Found {gadgets.Count} gadget(s)");

        foreach (var gadget in gadgets)
            Console.WriteLine($"|---> {gadget.Name} @ 0x{gadget.GadgetVa:X} - call @ 0x{gadget.CallVa:X}");
    }

    private static uint FileOffsetToRva(List<SectionInfo> secs, uint fileOffset)
    {
        return (from s in secs
            where fileOffset >= s.RawStart && fileOffset < s.RawStart + s.RawSize
            select s.VirtAddr + (fileOffset - s.RawStart)).FirstOrDefault();
    }

    private static ushort ReadUInt16(byte[] b, uint off) => BitConverter.ToUInt16(b, (int)off);
    private static uint ReadUInt32(byte[] b, uint off) => BitConverter.ToUInt32(b, (int)off);
    private static ulong ReadUInt64(byte[] b, uint off) => BitConverter.ToUInt64(b, (int)off);

    private static string ReadAsciiString(byte[] data, uint offset, int maxLen)
    {
        var end = (int)Math.Min(data.Length - offset, maxLen);
        return Encoding.ASCII.GetString(data, (int)offset, end).TrimEnd('\0');
    }
}

internal struct SectionInfo
{
    public string Name;
    public uint RawStart;
    public uint RawSize;
    public uint VirtAddr;
    public uint VirtSize;
    public uint Characteristics;
}

internal class Gadget(string name, ulong gVa, ulong cVa)
{
    public string Name { get; } = name;
    public ulong GadgetVa { get; } = gVa;
    public ulong CallVa { get; } = cVa;
}