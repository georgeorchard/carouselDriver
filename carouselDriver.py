import socket
import sys
import threading
import datetime
import struct



#Global Value for Current Command
currentCommand = ""

#global message ID
messageID = 0

#Define the commands
commands = {
    "COMMAND_CAROUSEL_CONFIG": 87,
    "COMMAND_CAROUSEL_ADD_STREAM": 82,
    "COMMAND_CAROUSEL_START": 80,
    "COMMAND_CAROUSEL_STOP": 85,
    "COMMAND_SEND_HINT": 70,
    "RESPONSE_CAROUSEL_ACK": 88,
    "RESPONSE_CAROUSEL_ERR": 89
}
commands_by_value = {value: key for key, value in commands.items()}

def getTimestampString():
    """
    Function to get the timestamp string
    Parameters: 
    None
    Returns
    timeStampString(String)
    """
    # Get the current time
    current_time = datetime.datetime.now().time()

    # Format the time as HH:MM:SS string
    timeStampString = current_time.strftime('%H:%M:%S')
    timeStampString = f"[{timeStampString}] "
    return(timeStampString)
    
#***
#CONNECTIVITY FUNCTIONS
#***
def connectTCP(ip, port):
    """
    Function to connect to the TCP port of the encoder
    Parameters:
    ip(String): The IP address of the encoder
    port(int): The port of the encoder
    Returns:
    encoderSocket (Socket): The socket
    """
    #Create the TCP socket
    encoderSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    # Get the current time
    timestamp_string = getTimestampString()
    

    
    #Connect to the socket
        
    try:
        encoderSocket.connect((ip, port))
        print(f"[{timestamp_string}] Connected to {ip}:{port}")


    except ConnectionRefusedError:
        print(f"[{timestamp_string}] Connection was refused. Ensure the server is running or check the IP and port.")
    except Exception as e:
        print(f"An error occurred: {e}")

    # Return the socket
    return encoderSocket
    
    
def sendMessageTCP(socket, message):
    """
    A function to send a message on a given socket
    Parameters:
    socket (Socket): The socket to send on
    messasge (String) The message to send
    Returns:
    code(int): The return code
    """
    lock.acquire()
    binaryData = bytes.fromhex(message)
    socket.send(binaryData)
    lock.release()
    
    
def listenToSocket(socket):
    """
    A function to listen on the given socket and react accordingly
    Parameters:
    socket (Socket): The socket to send on
    Returns:
    None
    """
    while True:
        try:
            """
            # Receive data from the socket
            data = socket.recv(1024)
            hex_string = ''.join([hex(byte)[2:].zfill(2) for byte in data])
            #output what the command is
            commandValue = int(hex_string[4:6])
            commandName = commands_by_value.get(commandValue)
            """
            
            rawData = socket.recv(450)
            #remove the TCP header (44 bytes)
            data = rawData[44:]
            
            #split the information
            hex_string = ''.join([hex(byte)[2:].zfill(2) for byte in data])
            
            #get the command
            commandValue = int(hex_string[4:8], 16)
            commandName = commands_by_value.get(commandValue)
            
            #take away the information (6 bytes)
            data = data[6:]
            hex_string = ''.join([hex(byte)[2:].zfill(2) for byte in data])

            #get the data length (4 byte big endian structure at byte 13,14,15,16 (index 12,13,14,15))
            dataLength = int(hex_string[24:32], 16)
            
            
            #decode the actual data
            # Extract data after the 12th byte (excluding the 12th byte)
            #up to the data length 12 bytes to 12 + data length
            if (dataLength != 0):
                dataTrimmed = data[12:(12+dataLength)]
                
                decodedString = dataTrimmed.decode('ascii')
                seperatedString = decodedString.split(',')
            
            
            
            print(f"{getTimestampString()}Received Message of type {commandName} from Primary Carousel")
            global debugMode
            if not data:
                break
            global currentCommand
            #If an ACK is received, respond based on the current command.
            if commandName == "RESPONSE_CAROUSEL_ACK":
                if currentCommand = "COMMAND_CAROUSEL_CONFIG":
                    print(f"{getTimestampString()}Primary Carousel ACCEPTED the config")
                elif currentCommand = "COMMAND_CAROUSEL_ADD_STREAM":
                    print(f"{getTimestampString()}Primary Carousel ACCEPTED the added stream")
                elif currentCommand = "COMMAND_CAROUSEL_START":
                    print(f"{getTimestampString()}Primary Carousel STARTED")
                elif currentCommand = "COMMAND_CAROUSEL_STOP":
                    #print the cycle count - bytes 17,18,19,20 
                    cycleCount = int(hex_string[32:40], 16)
                    print(f"{getTimestampString()}Primary Carousel STOPPED, cycle count {cycleCount}")
                    
                    
                elif currentCommand = "COMMAND_SEND_HINT":
                    #get hint data
                    programID = int(seperatedString[0])
                    eventID = int(seperatedString[1])
                    print(f"{getTimestampString()}Primary Carousel ACCEPTED the hint for program ID {programID}, hint ID {hintID}")
                    #get data about the hint
                    """
                    programID = int(hex_string[8:10])
                    eventID = int([10:12])
                    """
                    
                    startCarousel(programID, eventID)
                    
            if commandName == "RESPONSE_CAROUSEL_ERR":
                if currentCommand = "COMMAND_CAROUSEL_CONFIG":
                    print(f"{getTimestampString()}Primary Carousel REJECTED the config")
                elif currentCommand = "COMMAND_CAROUSEL_ADD_STREAM":
                    print(f"{getTimestampString()}Primary Carousel REJECTED the added stream")
                elif currentCommand = "COMMAND_CAROUSEL_START":
                    print(f"{getTimestampString()}Primary Carousel FAILED to start")
                elif currentCommand = "COMMAND_CAROUSEL_STOP":
                    print(f"{getTimestampString()}Primary Carousel FAILED to stop")
                elif currentCommand = "COMMAND_SEND_HINT":
                    print(f"{getTimestampString()}Primary Carousel REJECTED the hint")
                    
                
                
        except Exception as e:
            print(f"An error occurred: {e}")
            break

    # Close the socket when done
    socket.close()

def sendHints(programID, eventID, hintConfigFile):
    """
    A function to open the hintConfig file and send the hints inside to the carousel
    Parameters:
    programID: The program ID to send the hints on.
    eventID: The event that the hint is being sent for
    hintConfigFile: The config file for the hints
    Returns:
    None
    """
    with open('hintsConfig.csv', 'r') as file:
        # Skip the first line (headers)
        next(file)
        # Read each line of the CSV file
        for line in file:
            # Split the line by comma (assuming it's a CSV file)
            columns = line.strip().split(',')
            programIDFile = columns[0]
            eventIDFile = columns[1]

            #check we have the correct hint set
            if(programIDFile == programID and eventIDFile == eventID):
                hintCount = columns[2]
                payload = columns[3]
                
                hintMessage = create_hint_message(0,0,eventID,hintCount,payload)
                #encode the hint message
                hintMessage = hintMessage.encode('ascii')
                packet = createPacket("COMMAND_SEND_HINT", hintMessage, programID)
                sendMessageTCP(packet)
                print(f"{getTimestampString()}Sending Hint for Program ID {programID} for Event ID {eventID}")
                
                
            else:
                print(f"{getTimestampString()}ERROR: Hint set not found in Hint Config file for Program ID {programIDFile} and Event ID {EventIDFile}")


def create_hint_message(clock, day, event_Id, count, load):
    """
    Creates a hint message object based on the provided parameters and returns it as a formatted string.
    
    Parameters:
    clock: The clock value.
    day: The day value.
    event_Id: The event ID.
    count: The count value.
    length: The length of the payload.
    load: The byte array representing the payload.
    
    Returns:
    A formatted string representing the hint message.
    """
    #get the length of the data in bytes
    length = len(load)
    payload = bytearray(length)

    if length > 0:
        payload[:length] = load[:length]

    hint_message = f"{clock},{day},{event_Id},{count},{length},{payload}"
    

    return hint_message       
    
    
    
        
def createPacket(command, data, programID):
    """
    A function to create the packet of data to be sent on the socket
    Parameters:
    Command(String): The command 
    Data(String): The data
    programID(string): The program ID to include
    Returns:
    Packet: The return packet
    """
    #update the global messageID
    global messageID
    messageID += 1
    
    # Convert command to a single byte
    #command_byte = struct.pack('B', commands.get(command))
    command_byte = command.to_bytes(1, byteorder='big')
    
    #already encoded
    data_bytes = data
    
    
    
    
    #content - all 32 bit (4 byte) integers BIG ENDIAN
    #messageID - increment on each message
    messageIDBytes = messageID.to_bytes(4, byteorder='big')
    #channelID - the channel
    channelIDBytes = channelID.to_bytes(4, byteorder='big')
    #eventID - all 0
    eventID = 0
    eventIDBytes = eventID.to_bytes(4, byteorder='big')
    #Payload LENGTH
    # Get the length of data after converting to bytes
    data_length = len(data_bytes)

    # Convert data length to two bytes
    data_length_bytes = data_length.to_bytes(4, byteorder='big')
    
    
    #cycle count - not in HINT - 0
    cycleCount = 0
    cycleCountBytes = cycleCount.to_bytes(4, byteorder='big')
    #section count - not in HINT - 0
    sectionCount = 0
    sectionCountBytes = sectionCount.to_bytes(4, byteorder='big')

    
    

    
    #pad with bytes of 00 to make data 300
    # Calculate the required padding length
    padding_length = 300 - data_length

    # Add padding with bytes of 0x00
    data_bytes += b'\x00' * padding_length



    #data length of entire thing
    #24 for pre-data content
    #300 for data bytes
    dataLengthEntirePacket = len(content) + len(data_bytes)
    dataLengthEntirePacketBytes = dataLengthEntirePacket.to_bytes(2, byteorder='big')
    
    
    # Combine all parts of the packet
    #create content
    #dont sent certain aspects if sending HINT
    if(command != "COMMAND_SEND_HINT"):
        content = messageIDBytes+channelIDBytes+eventIDBytes+data_length_bytes+cycleCountBytes+sectionCountBytes
    else:
        content = messageIDBytes+channelIDBytes+eventIDBytes+data_length_bytes
    #ushort is 2 bytes
    
    packet = b'\x00\x00\x00' + command_byte + dataLengthEntirePacketBytes + content + data_bytes
    
    
    
    #add padding to make packet 406 bytes
    padding_length = 406 - len(packet)

    # Add padding with bytes of 0x00
    packet += b'\x00' * padding_length

    
    
    #update the current command
    global currentCommand
    currentCommand = commands_by_value.get(command)

    return packet


def addServices(servicesConfigFile):
    """
    A function to add services to the carousel
    Parameters:
    servicesConfigFile: The services file
    Returns:
    None
    """
    with open(servicesConfigFile, 'r') as file:
        """
        # Skip the first line (headers)
        next(file)
        """
        #skip the first 3 lines (headers)
        for i in range (0,3):
            next(file)
        # Read each line of the CSV file
        for line in file:
            # Split the line by comma (assuming it's a CSV file)
            columns = line.strip().split(',')
            if (len(columns) != 5):
                print(f"{getTimestampString()}Carousel Config File Error: Carousel Data Insufficient")
                break
            scte35_Service_Id = columns[0]
            scte35_PID = columns[1]
            scte35_Rate = columns[2]
            channelName = columns[3]
            channelTag = columns[4]
            #create the string
            string = f"{scte35_Service_Id},{scte35_PID},{scte35_Rate},{channelName},{channelTag}"
            #convert to bytes
            bytesToSend = string.encode('ascii')
            packet = createPacket("COMMAND_CAROUSEL_ADD_STREAM", bytesToSend, channelTag)

            sendMessageTCP(packet)
            print(f"{getTimestampString()}Adding Stream {channelName} to Primary Carousel")
            
 
def parseEvents(eventsScheduleFile):
    """
    A function to parse SCTE Events from a text file, used to drive the Trigger Manager for POC purposes
    Parameters:
    eventsScheduleFile: The file containing the events schedule
    Returns:
    None
    """
    eventsSchedule = []
    with open(eventsScheduleFile, 'r') as file:
        # Skip the first line (headers)
        next(file)
        # Read each line of the CSV file
        for line in file:
            # Split the line by comma (assuming it's a CSV file)
            columns = line.strip().split(',')
            programID = columns[0]
            eventID = columns[1]
            time = columns[2]
            
            timeSplit = time.strip().split(':')
            hours = timeSplit[0]
            mins = timeSplit[1]
            secs = timeSplit[2]
            #get current time
            currentTime = datetime.datetime.now()
            formattedTime = currentTime.strftime("%H:%M:%S")
            formattedTimeSplit = formattedTime.split(':')
            currentHours = formattedTimeSplit[0]
            currentMins = formattedTimeSplit[1]
            currentSecs = formattedTimeSplit[2]
            #work out the time to the event, take away the 10 seconds to allow for the time the message would be sent beforehand.
            timeToEvent = ((hours*3600 + mins*60 + secs) - (currentHours*3600 + currentMins*60 + currentSecs)) - 10
            if(timeToEvent > 0):
                time.sleep(timeToEvent)
                print(f"{getTimestampString()}Processing Hints for Program ID {programID}, Event ID {eventID}")
                sendHints(programID, eventID, hintConfigFile)
                #stop the carousel after the event time.
                time.sleep(10)
                stopCarousel(programID, eventID)

def startCarousel(programID, eventID):
    """
    Function to start the carousel
    Parameters: 
    programID: The program ID
    eventID: The event ID
    Returns:
    None
    """
    #create the string
    string = f"{programID},{eventID}"
    #convert to bytes
    bytesToSend = string.encode('ascii')
    packet = createPacket("COMMAND_CAROUSEL_START", bytesToSend, programID)
    sendMessageTCP(packet)
    print(f"{getTimestampString()}Starting Primary Carousel for Program ID {programID}, Event ID {eventID}")
    
    
    
def stopCarousel(programID, eventID):
    """
    Function to stop the carousel
    Parameters: 
    programID: The program ID
    eventID: The event ID
    Returns:
    None
    """
    #create the string
    string = f"{programID},{eventID}"
    #convert to bytes
    bytesToSend = string.encode('ascii')
    packet = createPacket("COMMAND_CAROUSEL_STOP", bytesToSend, programID)
    sendMessageTCP(packet)
    print(f"{getTimestampString()}Stopping Primary Carousel for Program ID {programID}, Event ID {eventID}")
    

def configureCarousel(carouselConfig):
    """
    A function to configure the carousel
    Parameters:
    carouselConfig: The name of the carousel config file
    Returns:
    None
    """
    with open(carouselConfigFile, 'r') as file:
        # Skip the first line (headers)
        next(file)
        line = next(file)
        #if empty
        if not line:
            print(f"{getTimestampString()}Carousel Config File Error: No Carousel Data")
            break
        columns = line.strip().split(',')
        if (len(columns) != 13):
            print(f"{getTimestampString()}Carousel Config File Error: Carousel Data Insufficient")
            break
        carouselIP = columns[0]
        carouselPort = columns[1]
        hintIP = columns[2]
        hintPort = columns[3]
        streamDestIP = columns[4]
        streamDestPort = columns[5]
        bitrate = columns[6]  
        patRate = columns[7]
        pmtRate = columns[8]
        pmtPID = columns[9]
        streamSourceIP = columns[10]
        streamSourcePort = columns[11]
        hintDelay = columns[12]
        
        
        #create the string
        string = f"{hintIP},{hintPort},{streamSourceIP},{streamSourcePort},{streamDestIP},{streamDestPort},{bitrate},{patRate},{pmtRate},{pmtPort}"
        #convert to bytes
        bytesToSend = string.encode('ascii')
        packet = createPacket("COMMAND_CAROUSEL_START", bytesToSend, 0)
   
        sendMessageTCP(packet)
        print(f"{getTimestampString()}Sending Carousel Config Data")

            

#Main
if __name__ == "__main__":

    #Global value for program version
    programVersion = 1.0.0
    print(f"Encoder Driver Version: {programVersion}")
    
    #set file names
    hintConfigFile = "hintConfig.csv"
    carouselConfigFile = "carouselConfig.csv"
    #servicesConfigFile = "servicesConfig.csv"
    eventsScheduleFile = "eventSchedule.csv"
    


    #Connect to the Carousel from the carousel config file.
    ip = ""
    port = 0
    with open(carouselConfigFile, 'r') as file:
        # Skip the first line (headers)
        next(file)
        # Read each line of the CSV file
        for line in file:
            # Split the line by comma (assuming it's a CSV file)
            columns = line.strip().split(',')
            ip = columns[0]
            port = columns[1]
    print(f"{getTimestampString()}Connecting to Primary Carousel at {ip}:{port}")
    socket = connectTCP(ip, port)
    #start receiving data from the carousel
    receiveThread = threading.Thread(target=listenToSocket, args=(socket,))
    receiveThread.daemon = True
    receiveThread.start()
    
    #send config message from TM to Carousel
    #NEED NEW VERSION OF CAROUSEL CODE.
    configureCarousel(carouselConfigFile)
    
    #add the services to the carousel
    addServices(carouselConfigFile)
    
    #Get a schedule of the events
    parseEvents(eventsScheduleFile)
    
    
    
    #Close Carousel connection
    print(f"{getTimestampString()}Closing connection to Primary Carousel at {ip}:{port}")
    socket.close()
    
    
    
   