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
    broadcast_counter = 0
    last_time=0
    print_count=0
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
	except IndexError: pass
	except ValueError: pass


log_files=list_files()
log=parse_files(log_files)


