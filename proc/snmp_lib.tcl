
#define TYPE_OTHER          0
#define TYPE_OBJID          1 v
#define TYPE_OCTETSTR       2 v
#define TYPE_INTEGER        3 v
#define TYPE_NETADDR        4
#define TYPE_IPADDR         5
#define TYPE_COUNTER        6
#define TYPE_GAUGE          7
#define TYPE_TIMETICKS      8
#define TYPE_OPAQUE         9
#define TYPE_NULL           10
#define TYPE_COUNTER64      11
#define TYPE_BITSTRING      12 v ASN_OCTET_STR
#define TYPE_NSAPADDRESS    13
#define TYPE_UINTEGER       14
#define TYPE_UNSIGNED32     15
#define TYPE_INTEGER32      16 v
     # * defined types (from the SMI, RFC 1157) 1155
     # */
#define ASN_IPADDRESS   (ASN_APPLICATION | 0)
#define ASN_COUNTER	(ASN_APPLICATION | 1)
#define ASN_GAUGE	(ASN_APPLICATION | 2)
#define ASN_UNSIGNED    (ASN_APPLICATION | 2)   /* RFC 1902 - same as GAUGE */
#define ASN_TIMETICKS   (ASN_APPLICATION | 3)
#define ASN_OPAQUE	(ASN_APPLICATION | 4)   /* changed so no conflict with other includes */

    # /*
     # * defined types (from the SMI, RFC 1442) 
     # */
#define ASN_NSAP	(ASN_APPLICATION | 5)   /* historic - don't use */
#define ASN_COUNTER64   (ASN_APPLICATION | 6)
#define ASN_UINTEGER    (ASN_APPLICATION | 7)   /* historic - don't use */

#ifdef NETSNMP_WITH_OPAQUE_SPECIAL_TYPES
    # /*
     # * defined types from draft-perkins-opaque-01.txt 
     # */
#define ASN_FLOAT	    (ASN_APPLICATION | 8)
#define ASN_DOUBLE	    (ASN_APPLICATION | 9)
#define ASN_INTEGER64        (ASN_APPLICATION | 10)
#define ASN_UNSIGNED64       (ASN_APPLICATION | 11)

#define ASN_BOOLEAN	    ((u_char)0x01)
#define ASN_INTEGER	    ((u_char)0x02)
#define ASN_BIT_STR	    ((u_char)0x03)
#define ASN_OCTET_STR	    ((u_char)0x04)
#define ASN_NULL	    ((u_char)0x05)
#define ASN_OBJECT_ID	    ((u_char)0x06)
#define ASN_SEQUENCE	    ((u_char)0x10)
#define ASN_SET		    ((u_char)0x11)

#define ASN_UNIVERSAL	    ((u_char)0x00)
#define ASN_APPLICATION     ((u_char)0x40)
#define ASN_CONTEXT	    ((u_char)0x80)
#define ASN_PRIVATE	    ((u_char)0xC0)

#define ASN_PRIMITIVE	    ((u_char)0x00)
#define ASN_CONSTRUCTOR	    ((u_char)0x20)

#define ASN_LONG_LEN	    (0x80)
#define ASN_EXTENSION_ID    (0x1F)
#define ASN_BIT8	    (0x80)

if {![namespace exist asn]} {
	package require asn
}


namespace eval snmp {
	# rfc1448 1157 1155 9f7b integer64
	variable PDU_TYPE
	variable Value_TYPE
	array set PDU_TYPE {
		GetRequest 160
		GetNextRequest 161
		Response 162
		SetRequest 163
		GetBulkRequest 165
		InformRequest 166
		SNMPv2-Trap-PDU 167
		160 GetRequest
		161 GetNextRequest
		162 Response
		163 SetRequest
		165 GetBulkRequest
		166 InformRequest
		167 SNMPv2-Trap-PDU
	}
	set Value_TYPE(2) INTEGER
	set Value_TYPE(4) OCTET_STR
	set Value_TYPE(6) OBJECT_ID
	set Value_TYPE([expr 64|0]) IPADDRESS
	set Value_TYPE([expr 64|1]) COUNTER
	set Value_TYPE([expr 64|2]) UNSIGNED
	set Value_TYPE([expr 64|3]) TIMETICKS
	# set Value_TYPE([expr 64|4]) TIMETICKS
	# set Value_TYPE([expr 64|5]) TIMETICKS
	set Value_TYPE([expr 64|6]) COUNTER64
	# set Value_TYPE([expr 64|7]) TIMETICKS
}


proc ::asn::GetFullTag {tag class constr} {
	#asn.1(ITU-T X.690)
	switch $class {
		UNIVERSAL {
			set tag [expr $tag | 0x00]
		}
		APPLICATION {
			set tag [expr $tag | 0x40]
		}
		CONTEXT {
			set tag [expr $tag | 0x80]
		}
		PRIVATE {
			set tag [expr $tag | 0xc0]
		}
	}
	set tag [expr $tag | ($constr<<5)]
	return $tag
}


#=========================================
#
#
#
#=========================================
proc ::snmp::decode_snmp_packet {data ver comm type id vbind } {
	variable PDU_TYPE
	upvar $ver myver $comm mycomm $type mytype $vbind myvbind $id myid	
	set rawdata $data
	if [catch {::asn::asnGetSequence data data} ret] {
		show_err_message "decode_snmp_packet 01\n"
		show_err_message "[showhex $rawdata]"
		show_err_message "$ret \n"
		return -1
	}
	# snmp version
	set rawdata $data
	if [catch {::asn::asnGetInteger data myver} ret] {
		show_err_message "decode_snmp_packet 02\n"
		show_err_message "[showhex $rawdata]"
		show_err_message "$ret \n"
		return -1
	}

	# snmp community
	set rawdata $data
	if [catch {::asn::asnGetOctetString data mycomm} ret] {
		show_err_message "decode_snmp_packet 03\n"
		show_err_message "[showhex $rawdata]"
		show_err_message "$ret \n"
		return -1
	}
	
	# snmp method type
	set rawdata $data
	if [catch {
		::asn::asnGetContext data mytype
		::asn::asnGetInteger data myid
		::asn::asnGetInteger data err
		::asn::asnGetInteger data err_ind	
		::asn::asnGetSequence data data
	} ret] {
		show_err_message "decode_snmp_packet 04\n"
		show_err_message "[showhex $rawdata]"
		show_err_message "$ret \n"
	}
	# VBind data(s)
	set myvbind $data
	return $err
}

# GetRequest 160
# GetNextRequest 161
# Response 162
# SetRequest 163
# GetBulkRequest 165
# InformRequest 166
# SNMPv2-Trap-PDU 167
proc ::snmp::encode_snmp_packet {ver comm type id vbind } {
	variable PDU_TYPE
	set temp ""
	append temp [::asn::asnInteger $id]
	append temp [::asn::asnInteger 0]
	append temp [::asn::asnInteger 0]
	append temp [::asn::asnSequence $vbind]
	
	set temp [::asn::asnContextConstr $type $temp]
	# set temp [::asn::asnSequence $temp]
	# ::asn::asnRetag temp $PDU_TYPE($type)
	set snmp_packet ""	
	append snmp_packet [::asn::asnInteger $ver]
	append snmp_packet [::asn::asnOctetString  $comm]
	append snmp_packet $temp
	set snmp_packet [::asn::asnSequence $snmp_packet]
	return $snmp_packet	
}

proc ::snmp::GetValueType {data} {
	variable Value_TYPE
	::asn::asnPeekTag data tag class constr
	if [info exist Value_TYPE([::asn::GetFullTag $tag $class $constr])] {
		return $Value_TYPE([::asn::GetFullTag $tag $class $constr])
	} else {
		return unkmow
	}
}

proc ::snmp::Decode_VBind {data_var oid_var type_var value_var} {
	upvar $data_var data $type_var type $value_var value $oid_var oid
	::asn::asnGetSequence data item	
	::snmp::Decode_value item type oid	
	::snmp::Decode_value item type value
}

proc ::snmp::Encode_VBind {oid {type null} {value ""} } {
	set vbind ""
	append vbind [::asn::asnObjectIdentifier [split $oid .]]
	switch $type {
		s {
			append vbind [::asn::asnOctetString $value]
		}
		x {			
			append vbind [::asn::asnOctetString [binary format H* $value]]
		}
		i {
			append vbind [::asn::asnInteger $value]		 
		}
		null {
			append vbind [::asn::asnNull ]
		}		
	}
	
	set vbind [::asn::asnSequence $vbind]
	return $vbind
}

# ::snmp::Decode_OID {data oid} {
	# upvar $data mydata
	# :snmp::Decode_value $
# }

proc ::snmp::Decode_value {data_var type_var value_var} {
	upvar $data_var data $type_var type $value_var value
	set type [::snmp::GetValueType $data]
	set value ""
	switch $type {
		INTEGER {
			::asn::asnGetInteger data value
		}
		OCTET_STR {
			::asn::asnGetOctetString data value
			if {![string is print $value]} {
				binary scan $value H* value
				set value [string toupper $value]
			}
		}
		OBJECT_ID {
			::asn::asnGetObjectIdentifier data value
			set value [join $value .]
		}
		IPADDRESS {
			::asn::asnRetag data 0x04
			::asn::asnGetOctetString data value
			binary scan $value H2H2H2H2 ip1 ip2 ip3 ip4
			set value [expr 0x$ip1].[expr 0x$ip2].[expr 0x$ip3].[expr 0x$ip4]
		}		
		COUNTER {
			::asn::asnRetag data 0x02
			::asn::asnGetInteger data value
		}
		UNSIGNED {
			::asn::asnRetag data 0x02
			::asn::asnGetInteger data value
		}
		TIMETICKS {
			::asn::asnRetag data 0x02
			::asn::asnGetInteger data value
		}
		COUNTER64 {
		}
		default {
			::asn::asnRetag data 0x04
			::asn::asnGetOctetString data value
			binary scan $value H* value
		}
	}
	# puts "value = $value ($type)"
	# puts "Decode_value [string length $data]"
}


proc ::snmp::snmpset {ip comm ver args} {
	foreach {oid type value} $args {
		append vbind [::snmp::Encode_VBind $oid $type $value]
	}
	set ::snmp::tempid [expr int (rand()*100000)]
	set pdu [::snmp::encode_snmp_packet $ver $comm 3 $::snmp::tempid $vbind]
	set ::snmp::tempsock [udp_open]
	fconfigure $::snmp::tempsock -buffering none -translation binary -encoding binary -remote [list $ip 161]
	fileevent $::snmp::tempsock readable {
		set data [read $::snmp::tempsock]
		set err [::snmp::decode_snmp_packet $data ret_ver ret_comm ret_pdutype ret_id ret_vbinds]
		puts "ver=$ret_ver comm=$ret_comm pdutype=$ret_pdutype id=$ret_id"
		puts "myid=$::snmp::tempid"
		if {$::snmp::tempid==$ret_id} {
			after cancel  $::snmp::timeoutid
			set ::snmp::wait $err
		}		
	}
	set ::snmp::timeoutid [after 1000 {		
		puts "after end"
		set ::snmp::wait 2
	}]
	
	puts -nonewline $::snmp::tempsock $pdu	
	vwait ::snmp::wait
	puts ret=$::snmp::wait
	switch $::snmp::wait {
		1 {
			puts "snmp error"
			return 0
		}
		2 {
			puts "snmp timeout"
			return 0
		}
		default {
			puts "default"
			return 1
		}
	}	
}
