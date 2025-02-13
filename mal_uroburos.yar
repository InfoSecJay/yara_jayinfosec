import "pe"

// Compose one rule that is specific or precise, with a lot of high-quality, unique PE export features that will catch this exact sample.

rule MAL_Uroburos_PE_Export_Features_hifi {
    meta:
        description = "Uroburos malware yara rule focusing on PE export features."
        author = "jtymchuk"
        date = "2025-02-13"
        references = "https://malpedia.caad.fkie.fraunhofer.de/details/win.uroburos"
        hash = "d597e4a61d94180044dfb616701e5e539f27eeecfae827fb024c114e30c54914"
    condition:
        uint16be(0) == 0x4d5a // MZ header
        and pe.number_of_signatures == 0
        and pe.export_timestamp == 1359984004
        and pe.dll_name == "inj_snake_Win32.dll"
        and pe.number_of_exports >= 60
        and (pe.version_info["OriginalFilename"] icontains "charmap"             
        and not pe.version_info["OriginalFilename"] icontains "charmap.exe")
}


// Compose another rule that is “broader” or “looser” or less specific, that will catch this and other samples of the same malware.

rule MAL_Uroburos_PE_Export_Features_lowfi {
    meta:
        description = "Uroburos malware yara rule focusing on PE export features."
        author = "jtymchuk"
        date = "2025-02-13"
        references = "https://malpedia.caad.fkie.fraunhofer.de/details/win.uroburos"
        hash = "d597e4a61d94180044dfb616701e5e539f27eeecfae827fb024c114e30c54914"  
    condition:
        uint16be(0) == 0x4d5a // MZ header
        and pe.number_of_signatures == 0
        and pe.number_of_exports >= 40
        and for 2 thing in pe.export_details:
            (thing.name contains "snake_")
        and for 10 thing in pe.export_details:
            (thing.name matches /^[a-z]{2}_/)
}

// Try to identify anything unusual or atypical about how this malware implements its exports and try to invent a third rule that detects a PE export “anomaly”.

rule Unusual_PE_Export_Features {
    meta:
        description = "Uroburos malware yara rule focusing on PE export features."
        author = "jtymchuk"
        date = "2025-02-13"
        references = "https://malpedia.caad.fkie.fraunhofer.de/details/win.uroburos"
        hash = "d597e4a61d94180044dfb616701e5e539f27eeecfae827fb024c114e30c54914"
    condition:
        uint16be(0) == 0x4d5a // MZ header
        and pe.number_of_signatures == 0
        and pe.number_of_exports >= 40 
        and pe.timestamp < pe.export_timestamp
}
