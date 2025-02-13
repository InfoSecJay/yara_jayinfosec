import "pe"

rule Malicious_Section_y0da_hard {
	meta:
		description = "PE with common malicious section name .y0da from 'Getting familiar with YARA syntax' quiz"
		author = "jtymchuk"
        references = "http://www.hexacorn.com/blog/2012/10/14/random-stats-from-1-2m-samples-pe-section-names/"
	condition:
        uint16be(0) == 0x4d5a and
        for any i in (0 .. pe.number_of_sections) : 
            (pe.sections[i].name == ".y0da")
}

rule Malicious_Section_y0da_easy {
	meta:
		description = "PE with common malicious section name .y0da from 'Getting familiar with YARA syntax' quiz"
		author = "jtymchuk"
        references = "http://www.hexacorn.com/blog/2012/10/14/random-stats-from-1-2m-samples-pe-section-names/"
	condition:
        uint16be(0) == 0x4d5a and
        for any section in pe.sections: 
            (section.name == ".y0da")
}
