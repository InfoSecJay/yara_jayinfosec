import "pe"
import "console"


rule MustangPanda_Downloader_Broad_Strings {
	meta:
		description = "Strings from Mustang Panda downloader, which may lead to PlugX malware"
		author = "jtymchukvv"
        references = "https://blog.talosintelligence.com/mustang-panda-targets-europe/"
		hash = "1b520e4dea36830a94a0c4ff92568ff8a9f2fbe70a7cedc79e01cea5ba0145b0"
	strings:
		$a1 = "/c ping 8.8.8.8 -n" wide
		$a2 = "cmd.exe" wide
		$a3 = "https" wide
		$a4 = "200 ok" wide
		$a5 = "200 OK" wide
        $a6 = "@abcdefghijklmnopqrstuvwxyz" wide
        $a7 = "COVID-19 travel restrictions EU reviews list of third countries.doc" wide
	condition:
		5 of them
}


rule MustangPanda_Downloader_Strings {

    meta:
        description = "Compose one rule that is specific or precise, with a lot of high-quality strings that catch this exact sample."
        author = "jtymchuk"
        date = "yy-mm-dd"
        references = "https://blog.talosintelligence.com/mustang-panda-targets-europe/"
        hash = "1b520e4dea36830a94a0c4ff92568ff8a9f2fbe70a7cedc79e01cea5ba0145b0"
    strings:
        $a = "45.154.14.235" wide
        $b1 = "PotPlayer.exe" wide
        $b2 = "PotPlayer.dll" wide
        $b3 = "PotPlayerDB.dat" wide
        $c = "/c ping 8.8.8.8 -n" wide
        $d = "200 ok" wide

    condition:
        uint16be(0) == 0x4d5a // MZ header
        and 2 of ($b*)
        and ($a or $c or $d) 
}

rule MustangPanda_pe_module {

    meta:
        description = "Makes use of the PE module to look for unique or interesting features."
        author = "Jay Tymchuk"
        date = "yy-mm-dd"
        references = "https://blog.talosintelligence.com/mustang-panda-targets-europe/"
        hash = "1b520e4dea36830a94a0c4ff92568ff8a9f2fbe70a7cedc79e01cea5ba0145b0"
    
    condition:
        uint16be(0) == 0x4d5a // MZ header
        and pe.number_of_signatures == 0
        and pe.number_of_resources > 20
}

