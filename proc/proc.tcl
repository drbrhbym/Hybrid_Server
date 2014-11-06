proc parse {sock} {
	#fconfigure $sock -buffering none -translation binary -encoding binary
	set data [read  $sock]
	foreach {host port} [udp_conf $sock -peer] {}
	fconfigure $sock -buffering none -translation binary -encoding binary -remote [list $host $port]
	if [snmp_inform_response $host $sock flow comm mac euro $data] {
		switch $flow {
			15 {
				# H-MTA-16 $euro $comm $host
				H-MTA-18 $mac $euro cfg_file cfg_hash
				H-MTA-19 $host $comm $euro $cfg_file $cfg_hash 
			}
		}
	}
}


#==========================================
# Flow H-MTA-16
# Query additional information for create config file
# Now get fqdn for test
#==========================================
proc H-MTA-16 {euro comm host} {
	log_msg "H-MTA-16~17:SNMPv2c GET Request(Option) \($host\)\n"
	log_msg "\tQuery MTA's FQDN\n"
	if {$euro} {
		catch {log_msg "\tFQDN = [snmp_get -t 3 -r 2 -v 2c -Oqv $host $comm .1.3.6.1.4.1.7432.1.1.1.4.0]\n"}
	} else {
		catch {log_msg "\tFQDN = [snmp_get -t 3 -r 2 -v 2c -Oqv $host $comm .1.3.6.1.4.1.4491.2.2.1.1.1.5.0]\n"}
	}
}

#==========================================
# Flow H-MTA-18
# Create config file and send to file server
# Now use pre configed file 
#==========================================
proc H-MTA-18 {mac euro file_var hash_var} {
	global client_data default_data
	upvar $file_var file $hash_var hash
	log_msg "H-MTA-18:Generate config file\n"
	log_msg "\tCurrently use pre defined config file\n"
	if [info exist client_data($mac,file)] {
		set file $client_data($mac,file)
		set hash $client_data($mac,hash)
	} else {
		switch $euro {
			"0" {
				set file $default_data(file)
				set hash $default_data(hash)
			}
			"1" {
				set file $default_data(eufile)
				set hash $default_data(euhash)
			}
			"2" {
				set file $default_data(20file)
				set hash $default_data(20hash)
			}
		}
	}
}

#==========================================
# Flow H-MTA-19
# set cfg_file and cfg_hash to mta that gert from H-MTA-18
# 
#==========================================

proc H-MTA-19 {host comm euro file hash} {
	global client_data default_data
	if {$::comm_enable} {
		set comm $::mycommunity
	}
	if {[string length $comm]==0} {
		log_msg "community is empty, use private\n" error
		set comm private
	}
	switch $euro {
		"0" {
			set oid(file) .1.3.6.1.4.1.4491.2.2.1.1.2.5.0
			set oid(hash) .1.3.6.1.4.1.4491.2.2.1.1.2.7.0
		}
		"1" {
			set oid(file) .1.3.6.1.4.1.7432.1.1.2.7.0
			set oid(hash) .1.3.6.1.4.1.7432.1.1.2.9.0
		}
		"2" {
			set oid(file) .1.3.6.1.2.1.140.1.2.9.0
			set oid(hash) .1.3.6.1.2.1.140.1.2.11.0
		}
	}
	
	log_msg "H-MTA-19:SNMPv2c Configuration File Set \($host\)\n"
	log_msg "\tMTA IP = $host , snmp community = $comm\n"
	log_msg "\tconfig file url = $file\n"
	log_msg "\tconfig file hash = $hash\n"

	if [catch {snmp_set -t 3 -r 2 -v 2c -c $comm $host $oid(file) s $file $oid(hash) x $hash} ret] {
		log_msg "snmpset fail: $ret\n" error
	}
}


#=================================================
# purpose: response snmp_inform_request
# if inform is ProvisioningStatus or ProvisioningEnrollment
# parse data
#=================================================
proc snmp_inform_response {host sock  flow_ptr comm_ptr mac_ptr eu_ptr data} {
	upvar $flow_ptr flow
	upvar $comm_ptr comm
	upvar $mac_ptr mac
	upvar $eu_ptr euro
	set flow 0
	set comm ""
	set mac ""
	set temp ""
	set euro 1
	set ::response_only 0
	#set data [read $sock]
	#binary scan $data H* zzz
	#puts  zzz=$zzz
	::snmp::decode_snmp_packet $data ver comm pdutype id vbinds
	# puts "ver=$ver comm=$comm pdutype=$pdutype"
	if {($ver!=1)||($pdutype!=6)} {return 0}
	#vBind data
	# snmp_inform vBind data format
	# 1 sysUpTime
	# 2 snmpTrapOID
	# 3-end snmpTrapOID'value
	# 1.sysUpTime
	::snmp::Decode_VBind vbinds oid type sysUpTime
	# 2.snmpTrapOID
	::snmp::Decode_VBind vbinds oid type snmpTrapOID
	switch $snmpTrapOID {
		"1.3.6.1.4.1.7432.1.2.0.1" {
			set euro 1
			set flow 15
		}
		"1.3.6.1.4.1.4491.2.2.1.2.0.1" {
			set euro 0
			set flow 15
		}
		"1.3.6.1.2.1.182.0.1" {
			set euro 2
			set flow 15
			puts pc20
		}
		"1.3.6.1.2.1.140.0.2" -
		"1.3.6.1.4.1.4491.2.2.1.2.0.2" -
		"1.3.6.1.4.1.7432.1.2.0.2" {
			parseProvisioningStatus $vbinds $host
		}
		"default" {
			set flow 0
		}
	}
	# get pktcMtaDevProvisioningEnrollment, get info for create config file
	if {$flow} {
		parseProvisioningEnrollment $vbinds $host $euro
	}
	# set newdata $temp
	set newdata [::snmp::encode_snmp_packet $ver $comm 2 $id $vbinds]
	puts -nonewline $sock $newdata
	return 1
}

# pktcMtaDevProvisioningEnrollment
# 1.sysDescr
# 2.pktcMtaDevSwCurrentVers
# 3.pktcMtaDevTypeIdentifier
# 4.ifPhysAddress
# 5.pktcMtaDevCorrelationId
proc parseProvisioningEnrollment {data host euro} {
	log_msg "H-MTA-15:SNMPv2c Enrollment INFORM \($host\)\n"
	::snmp::Decode_VBind data oid type sysDescr
	::snmp::Decode_VBind data oid type swver
	::snmp::Decode_VBind data oid type op60
	::snmp::Decode_VBind data oid type mac
	::snmp::Decode_VBind data oid type pktcMtaDevCorrelationId
	switch $euro {
		"0" {
			log_msg "\tMTA: $mac\n"
		}
		"1" {
			log_msg "\tEUMTA: $mac\n"
		}
		"2" {
			log_msg "\tPC20MTA: $mac\n"
		}
	}
	# if {$euro} {
		# log_msg "\tEUMTA: $mac\n"
	# } else {
		# log_msg "\tMTA: $mac\n"
	# }
	log_msg "\tsysDescr = $sysDescr\n"
}

# pktcMtaDevProvisioningStatus
# 1: ifPhysAddress
# 2: pktcMtaDevCorrelationId
# 3: pktcMtaDevProvisioningState
proc parseProvisioningStatus {data host} {
	::snmp::Decode_VBind data oid type mac
	::snmp::Decode_VBind data oid type id
	::snmp::Decode_VBind data oid type status
	log_msg "H-MTA-25:SNMPv2c Provisioning Status Inform (optional) \($host\)\n"
	log_msg "\tMAC=$mac\n"
	switch $status {
		"1" {log_msg "\tpass(1)\n" pass}
		"2" {log_msg "\tinProgress(2)\n" error}
		"3" {log_msg "\tfailConfigFileError(3)\n" error}
		"4" {log_msg "\tpassWithWarnings(4)\n" pass}
		"5" {log_msg "\tpassWithIncompleteParsing(5)\n" pass}
		"6" {log_msg "\tfailureInternalError(6)\n" error}
		"7" {log_msg "\tfailureOtherReason(7)\n" error}
	}
}
