import "pe"

rule MAL_BURNTCIGAR_Strings {
    meta:
        description = "BURNTCIGAR is a utility that terminates processes at the kernel level by exploiting an Avast driver’s undocumented IOCTL code"
        author = "jtymchuk"
        hash = "4306c5d152cdd86f3506f91633ef3ae7d8cf0dd25f3e37bec43423c4742f4c42"
    strings:
        $pe_header = "!This program cannot be run in DOS mode." ascii
        $proc_term1 = "CorExitProcess" ascii
        $proc_term2 = "Kill PID =" ascii
        $proc_term3 = "CreateFile Error = " ascii
        $pbd = "F:\\Source\\WorkNew19\\KillAV\\Release\\KillAV.pdb"
        $proc1 = "SentinelHelperService.exe" wide
        $proc2 = "SentinelServiceHost.exe" wide
        $proc3 = "SentinelStaticEngineScanner.exe" wide
        $proc4 = "Sentinel0Agent.exe" wide
        $proc5 = "SentinelAgentWorker.exe" wide
        $proc6 = "SentinelUI.exe" wide
        $proc7 = "SAVAdminService.exe" wide
        $proc8 = "SavService.exe" wide
        $proc9 = "SEDService.exe" wide
        $proc10 = "ALsvc.exe" wide
        $proc11 = "SophosCleanM64.exe" wide
        $proc12 = "SophosFS.exe" wide
        $proc13 = "SophosFileScanner.exe" wide
        $proc14 = "SophosHealth.exe" wide
        $proc15 = "Endpoint Agent Tray.exe" wide
        $proc16 = "EAServiceMonitor.exe" wide
        $proc17 = "MsMpEng.exe" wide
        $service_name1 = "\\\\.\\aswSP_ArPot2" wide
        $service_name2 = "\\\\.\\aswSP_Avar" wide
    condition: 
        // PE specific conditions
        uint16be(0) == 0x4d5a // MZ header
        and filesize < 1MB
        and pe.number_of_signatures == 0 
        and pe.pdb_path == "F:\\Source\\WorkNew19\\KillAV\\Release\\KillAV.pdb"
        
        // String specific conditions
        and ($pe_header
            and any of ($proc_term*)
            and $pbd 
            and 10 of ($proc*) 
            and any of ($service_name*))
}


// Major Changes:
// 1) Added meta information
// 2) Imporved formatting with indentation
// 3) String types of avoid confusion
// 4) Added import pe and pe information to condition logic
// 5) Changed grouping of strings to align with what they are (example: $proc for proceses and $service_name for the malicious service names)
// Note: I tried to preserve the original logic as much as I can and added some PE information for some practice. Some things, like the pdb, are probably not needed to be referenced twice in the same rule, this is just a demonstration.
