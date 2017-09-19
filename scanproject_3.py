import os 

output = open("report.txt","w")

def list_files(): #unpack the files in the directory
    log_files = []
    for root, directory, filenames in os.walk("."): #search through all filetypes in the current directory
        for file in filenames: #looking at each file...
            if file.endswith('.log'): #if it is a log file
                log_files.append(file) #add the file to a list of log files
    return log_files

def parse_files(log_files):
    file_number=0 #initialize number to count the number of files scanned
    for file in log_files: #iterate through the log files
	log = open(file, "r").read().splitlines() #store the lines of the log file as elements in a list
	log = filter(None, log) #remove any empty lines from the list
	print "\n"+log_files[file_number]+" -->     " #print the name of the file
	output.write("\n"+log_files[file_number]+" -->     \n")
	broadcast_search(log, log_files[file_number]) #print scan information for the file with broadcast_search 
	file_number+=1
    return log		

def broadcast_search(log, filename):
    source_address=[]
    dest_address=[]
    source_ip_list=[]
    source_ip=[]
    dest_ip=[]
    sv_scan_time=0
    dest_port_count=0
    sv_source_ip=""
    source_port_count=0
    dest_port_list=[]
    source_port_list=[]
    broadcast_counter = 0
    last_time=0
    last_time_sVscan=0 
    last_time_oscan=0
    oscan_count=0
    sVscan_count=0
    print_count=0
    R_flag_count=0
    P_flag_count=0
    S_flag_count=0
    per_flag_count=0
    n_flag_count=0
    for line in log: #iterating through the lines of a log file
	try:	
		time_list = line[:8].split(":") #create a list consisting of the time elements of a line
		time_floats = map(float,time_list) #change string values into floats
		time = 3600*time_floats[0]+60*time_floats[1]+time_floats[2] #calculate the number of seconds corresponding to the time of the line
	except IndexError: pass	
	except ValueError: pass
	try:
		if (line.split(" ")[5]=="(Broadcast)"): #if element 5 of a line contains the word "Broadcast" it is typically the start of a scan
		    broadcast_counter +=1 #count how many lines containing "broadcast" have been seen in a row
		    source_address = line.split(" ")[7] #extract the source IP from the line
		    dest_address = line.split(" ")[4] #extract the destination IP from the line
		    source_ip = ".".join(source_address.split(".")[:4]) #combine the source IP address into one string and ignore the port data
		    dest_ip = ".".join(dest_address.split(".")[:4]) #combine the destination IP address into one string and ignore the port data
		    try:
			source_port = source_address.split(".")[4] #extract the source port data from the line
			dest_port = dest_address.split(".")[4] #extract the source port data from the line
		    except IndexError:
			source_port = None
			dest_port = None
		    if (broadcast_counter<=1)& (abs(time-last_time)>=4.5): #only print the scan information if it is the first line in a row containing "broadcast" and it's been at least 4.5 seconds since the last first line
			print "    scanned from "+source_ip+" to "+dest_ip+" at "+line[:8]
			output.write("    scanned from "+source_ip+" to "+dest_ip+" at "+line[:8]+"\n")
	    	        source_ip_list.append(source_ip) #add the IP to a list of unique IPs
			last_time =time #reset the time since the last scan to be the current time
		else:
		    broadcast_counter = 0 #reset the broadcast file because the line does not contain broadcast
		    source_address = line.split(" ")[2] #extract the source IP from the line
		    dest_address = line.split(" ")[4] #extract the destination IP from the line
		    source_ip = ".".join(source_address.split(".")[:4]) #combine the source IP address into one string and ignore the port data
		    dest_ip = ".".join(dest_address.split(".")[:4]) #combine the destination IP address into one string and ignore the port data
		    try:
			source_port = source_address.split(".")[4] #extract the source port data from the line
			dest_port = dest_address.split(".")[4] #extract the source port data from the line
		    except IndexError:
			source_port = None
			dest_port = None
		if source_port not in source_port_list:
			source_port_list.append(source_port)
		if dest_port not in dest_port_list:
			dest_port_list.append(dest_port)

		if  line.find('ICMP echo request') == -1:
		    oscan_count=1
		if 'Flags' == line.split(" ")[5]: 		
		    flag_type = line.split(" ")[6][1]
		    if flag_type == 'R':
			R_flag_count+=1
		    if flag_type=='P':
 	    		sVscan_count, last_time_sVscan = sVscan_check(line, time, last_time_sVscan, sVscan_count)
			P_flag_count+=1
			sv_scan_time=":".join(time_list)
			sv_source_ip= source_ip
		    if flag_type == 'S':
			S_flag_count+=1
		    if flag_type == '.':
			per_flag_count+=1
		    if flag_type == 'n':
			n_flag_count+=1



	except IndexError: pass
	except ValueError: pass
    if len(dest_port_list)>1000:
	if P_flag_count==0:
	    print "nmap -sV from " + sv_source_ip + "at" + str(sv_scan_time)
	elif oscan_count>=1:
		print oscan_count
	    	print 'Scan Identified: -O scan'
	else:
	    	print 'Scan Identified: -Ss scan'
    elif len(dest_port_list)<75:
	print 'Scan Identified: -sn scan'
    else: print 'Scan Identified: -F scan'	

    #print "R flags:"+ str(R_flag_count)
    print "P flags:"+ str(P_flag_count)
    #print "S flags:"+ str(S_flag_count)
    #print ". flags:"+ str(per_flag_count)
    #print "n flags:"+ str(n_flag_count)
    #print "# source ports: " +str(len(source_port_list))
    print "# dest ports: " +str(len(dest_port_list))

    

def sVscan_check(line, time, last_time_sVscan, sVscan_count):
    sVscan_count+=1
    if (sVscan_count>1) & (abs(time-last_time_sVscan)>=1000):
	sVscan_count=1
    if (sVscan_count>=1): 
    	last_time_sVscan =time #reset the time since the last scan to be the current time
    return sVscan_count, last_time_sVscan


log_files=list_files()
log=parse_files(log_files)



