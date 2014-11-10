#!/usr/bin/wish
set appPath [file normalize [info script]]
if {[file type $appPath] == "link"} {set appPath [file readlink $appPath]}
set appPath [file dirname $appPath]

set ::auto_path [linsert $::auto_path 0 [file join $appPath lib]]
#lappend ::auto_path [file join $appPath lib]
package require Tk
package require tile
package require netsnmptcl
package require inifile
package require asn
package require udp


source [file join $appPath proc proc.tcl]
source [file join $appPath proc snmp_lib.tcl]

wm title . "PacketCable Provisioning Server (Hybrid Flow)"

# menu
menu .mbar -tearoff 0 
. configure -menu .mbar

menu .mbar.log -tearoff 0
.mbar add cascade -menu .mbar.log -label Log
.mbar.log add command -label "log to" -command {}

menu .mbar.help -tearoff 0
.mbar add cascade -menu .mbar.help -label Help
.mbar.help add command -label "Hybrid Flow" -command {}
.mbar.help add command -label "About..." -command {}

ttk::frame .fr1
ttk::frame .fr2

ttk::button .fr1.bt1 -text "Start" -command {
	if [start_server] {
		$LOG delete 1.0 end
		.fr1.bt1 configure -state disable
		.fr1.bt2 configure -state enable
		.fr1.bt3 configure -state enable
	}
}
ttk::button .fr1.bt2 -text "Reload" -state disable -command {
	close $::server
	$LOG delete 1.0 end
	start_server
}
ttk::button .fr1.bt3 -text "Stop" -state disable -command {
	close $::server
	.fr1.bt1 configure -state enable
	.fr1.bt2 configure -state disable
	.fr1.bt3 configure -state disable
}
ttk::entry  .fr1.en -textvariable ::mycommunity -state disable
set ::mycommunity public
checkbutton  .fr1.ck -text "Community" -variable ::comm_enable -command {
	if {$::comm_enable} {
		.fr1.en configure -state enable
	} else {
		.fr1.en configure -state disable
	}
}


set LOG [text .fr2.log]
set sv [::ttk::scrollbar .fr2.sv -orient vertical -command [list $LOG yview]]
$LOG configure -yscrollcommand [list $sv set]

grid .fr1 -row 0 -column 0 -padx 5 -pady 5 -sticky ws
grid .fr2 -row 1 -column 0 -padx 5 -pady 5 -sticky news

grid .fr1.bt1 -row 0 -column 0 -padx 5 -pady 5 -sticky news
grid .fr1.bt3 -row 0 -column 1 -padx 5 -pady 5 -sticky news
grid .fr1.bt2 -row 0 -column 2 -padx 5 -pady 5 -sticky news
grid .fr1.ck  -row 0 -column 3 -padx 5 -pady 5 -sticky news
grid .fr1.en  -row 0 -column 4 -padx 5 -pady 5 -sticky news


grid $LOG -row 0 -column 0 -pady 5 -sticky news
grid $sv  -row 0 -column 1 -pady 5 -sticky ns

grid columnconfigure .fr2 0 -weight 1
grid rowconfigure .fr2 0 -weight 1

grid columnconfigure . 0 -weight 1
grid rowconfigure . 1 -weight 1

$LOG tag  configure error -foreground red -font {"Arial" {9} {}}
$LOG tag  configure pass -foreground #00a000 -font {"Arial" {9} {}}
$LOG tag  configure default  -foreground black -font {"Arial" {9} {}}

proc start_server {} {
	global client_data default_data
	# check ini file
	if {![file exist config.ini]} {
		puts error
		return 0
	}
	set inifd [::ini::open config.ini r]
	# check default section                      
	if {![::ini::exists $inifd default pkfile]   } {return 0}
	if {![::ini::exists $inifd default pkhash]   } {return 0}
	if {![::ini::exists $inifd default eupkfile] } {return 0}
	if {![::ini::exists $inifd default eupkhash] } {return 0}
	if {![::ini::exists $inifd default pk20file] } {return 0}
	if {![::ini::exists $inifd default pk20hash] } {return 0}
	# load client data
	set clients [::ini::sections $inifd]
	# puts clients=$clients
	set del [lsearch $clients default]
	set clients [lreplace $clients $del $del]	
	foreach client $clients {		
		set client [string toupper $client]
		set file [::ini::value $inifd $client file]
		set hash [::ini::value $inifd $client hash]
		if {$file==""} {
			puts "$client 's config is empty, use default config file"
			continue
		}
		if {[string length $hash]!=40} {
			puts "hash error"
			continue
		}
		set client_data($client,file) $file
		set client_data($client,hash) $hash
	}
	set default_data(file)   [::ini::value $inifd default pkfile] 
	set default_data(hash)   [::ini::value $inifd default pkhash] 
	set default_data(eufile) [::ini::value $inifd default eupkfile]
	set default_data(euhash) [::ini::value $inifd default eupkhash]
	set default_data(20file) [::ini::value $inifd default pk20file]
	set default_data(20hash) [::ini::value $inifd default pk20hash]
	::ini::close $inifd 
	
	if  [catch {set ::server [udp_open 162]} ret] {
		tk_messageBox -message $ret -icon error
		return 0
	}
	fconfigure $::server -buffering full -buffersize 2000 -translation binary -encoding binary
	fileevent $::server readable [list parse $::server]
	return 1
}


#==================================================================
# Name: log_msg
# Input: msg status
# Purpose: print message in text, $status use for change color
# return: null
#==================================================================
proc log_msg {msg {status default}} {
	global LOG
	$LOG insert end "$msg"
	$LOG see end

	set index [$LOG index end]
	switch $status {
		"default" {
			$LOG tag add default $index-2l $index-1l
		}
		"error" {
			$LOG tag add error $index-2l $index-1l
		}
		"pass" {
			$LOG tag add pass $index-2l $index-1l
		}
	}
}
show_ver
