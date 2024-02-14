import socket
import sys
import threading
import datetime
import struct



#Global Value for Current Command
currentCommand = ""



#Define the commands
commands = {
    "COMMAND_CAROUSEL_CONFIG": 0,
    "COMMAND_CAROUSEL_ADD_STREAM": 1,
    "COMMAND_CAROUSEL_START": 2,
    "COMMAND_CAROUSEL_STOP": 3,
    "COMMAND_SEND_HINT": 4,
    "RESPONSE_CAROUSEL_ACK": 5,
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
            # Receive data from the socket
            data = socket.recv(1024)
            hex_string = ''.join([hex(byte)[2:].zfill(2) for byte in data])
            #output what the command is
            commandValue = int(hex_string[4:6])
            commandName = commands_by_value.get(commandValue)
            
            print(f"{getTimestampString()}Received Message of type {commands_by_value.get(commandName)} from Primary Carousel")
            global debugMode
            if not data:
                break
            global currentCommand
            #If an ACK is received, respond based on the current command.
            if commandName == "RESPONSE_CAROUSEL_ACK":
                if currentCommand = "COMMAND_CAROUSEL_CONFIG":
                    print(f"{getTimestampString()}Primary Carousel accepted the update")
                elif currentCommand = "COMMAND_CAROUSEL_ADD_STREAM":
                    print(f"{getTimestampString()}Primary Carousel accepted the added stream")
                elif currentCommand = "COMMAND_CAROUSEL_START":
                    print(f"{getTimestampString()}Primary Carousel STARTED")
                elif currentCommand = "COMMAND_CAROUSEL_STOP":
                    print(f"{getTimestampString()}Primary Carousel STOPPED")
                elif currentCommand = "COMMAND_SEND_HINT":
                    print(f"{getTimestampString()}Primary Carousel accepted the hint")
                    #get data about the hint
                    programID = int(hex_string[8:10])
                    eventID = int([10:12])
                    startCarousel(programID, eventID)
                
                
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
                packet = createPacket("COMMAND_SEND_HINT", hintMessage)
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

    hint_message = f"{clock}{day}{event_Id}{count}{length}{payload}"

    return hint_message       
    
    
    
        
def createPacket(command, data):
    """
    A function to create the packet of data to be sent on the socket
    Parameters:
    Command(String): The command 
    Data(String): The data
    Returns:
    Packet: The return packet
    """
    # Convert command to a single byte
    command_byte = struct.pack('B', commands.get(command))

    # Convert data to bytes
    #data_bytes = data.encode('utf-8')
    #already encoded
    data_bytes = data

    # Get the length of data after converting to bytes
    data_length = len(data_bytes)

    # Convert data length to two bytes
    data_length_bytes = data_length.to_bytes(2, byteorder='big')

    # Combine all parts of the packet
    packet = b'\x00\x00' + command_byte + data_length_bytes + data_bytes
    
    #update the current command
    global currentCommand
    currentCommand = command

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
        #skip the first 4 lines (headers and service already done)
        for i in range (0,4):
            next(file)
        # Read each line of the CSV file
        for line in file:
            if not line:
                print(f"{getTimestampString()}Carousel Config File Error: No Service Data")
                break
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
            #create the packet
            columns = [scte35_Service_Id, scte35_PID, scte35_Rate, channelName, channelTag]

            # Convert each integer value to bytes and concatenate them into a byte array
            byte_array = b''
            for value in columns:
                if isinstance(value, int):
                    byte_array += value.to_bytes(2, 'big')  # Convert integer to a 2 bytes
                elif isinstance(value, str):
                    byte_array += value.encode()           # Convert string to bytes
                else:
                    # Handle other types of values as needed
                    pass
            
            packet = createPacket("COMMAND_CAROUSEL_ADD_STREAM", byte_array)
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
    #startMessage = f"0{programID}{eventID}"
    columns = [programID, eventID]
    # Convert each integer value to bytes and concatenate them into a byte array
    byte_array = b''
    for value in columns:
        if isinstance(value, int):
            byte_array += value.to_bytes(2, 'big')  # Convert integer to a 2 bytes
        elif isinstance(value, str):
            byte_array += value.encode()           # Convert string to bytes
        else:
            # Handle other types of values as needed
            pass
    packet = createPacket("COMMAND_CAROUSEL_START", byte_array)
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
    #stopMessage = f"0{programID}{eventID}"
    #startMessage = f"0{programID}{eventID}"
    columns = [programID, eventID]
    # Convert each integer value to bytes and concatenate them into a byte array
    byte_array = b''
    for value in columns:
        if isinstance(value, int):
            byte_array += value.to_bytes(2, 'big')  # Convert integer to a 2 bytes
        elif isinstance(value, str):
            byte_array += value.encode()           # Convert string to bytes
        else:
            # Handle other types of values as needed
            pass
    packet = createPacket("COMMAND_CAROUSEL_STOP", byte_array)
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
        #skip next line to get to the services
        next(file)
        line = next(file)
        if not line:
            print(f"{getTimestampString()}Carousel Config File Error: No Service Data")
            break
        columns = line.strip().split(',')
        if (len(columns) != 5):
            print(f"{getTimestampString()}Carousel Config File Error: Service Data Insufficient")
            break
        scte35_Service_Id = columns[0]
        scte35_PID = columns[1]
        scte35_Rate = columns[2]
        channelName = columns[3]
        channelTag = columns[4]
        
        data = [channelName,channelTag,carouselIP,carouselPort,hintIP,hintPort,streamDestIP,streamDestPort,bitrate,patRate,pmtRate,pmtPID,scte35_Service_Id,scte35_PID,scte35_Rate,streamSourceIP,streamSourcePort,hintDelay]
        # Convert each integer value to bytes and concatenate them into a byte array
        byte_array = b''
        for value in data:
            if isinstance(value, int):
                byte_array += value.to_bytes(2, 'big')  # Convert integer to a 2 bytes
            elif isinstance(value, str):
                byte_array += value.encode()           # Convert string to bytes
            else:
                # Handle other types of values as needed
                pass
        packet = createPacket("COMMAND_CAROUSEL_CONFIG", byte_array)
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
    servicesConfigFile = "servicesConfig.csv"
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
    addServices(servicesConfigFile)
    
    #Get a schedule of the events
    parseEvents(eventsScheduleFile)
    
    
    
    #Close Carousel connection
    print(f"{getTimestampString()}Closing connection to Primary Carousel at {ip}:{port}")
    socket.close()
    
    
    
   