rule Cheat_Generic_Tool_Names
{
    meta:
        description = "Deteksi proses dengan nama umum cheat/injector"
        author = "ChatGPT"
        created = "2025-06-26"

    strings:
        $name1 = "cheatengine"
        $name2 = "injector"
        $name3 = "aimbot"
        $name4 = "modmenu"
        $name5 = "bypass"
        $name6 = "dll_inject"
        $name7 = "xenos"
        $name8 = "Extreme Injector"
        $name9 = "hacks"
        $name10 = "autoclicker"
        $name11 = "magicbullet"
        $name12 = "triggerbot"
        $name13 = "silentaim"
        $name14 = "dammage_boost"
        $name15 = "stamina"

    condition:
        any of them
}

rule Cheat_Memory_Signatures
{
    meta:
        description = "Deteksi signature cheat di memory"
        author = "ChatGPT"
        created = "2025-06-26"

    strings:
        $code1 = { 8B 45 F8 89 45 FC 8B 45 FC 89 45 F8 }
        $code2 = { 55 8B EC 83 EC 0C 53 56 57 }
        $code3 = "CreateRemoteThread"
        $code4 = "VirtualAllocEx"
        $code5 = "WriteProcessMemory"

    condition:
        2 of them
}
