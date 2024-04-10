# Description: This script listens for incoming connections from the client and processes the received data.
# It writes the received data to a CSV file and sends an acknowledgment back to the client.
import socket
import simplejson as json
import csv

# Create a socket object
s = socket.socket()

# Set socket options and bind to a specific address and port
print('Socket created')
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(('127.0.0.1', 9999))
s.listen(5)

print('Waiting for connections')

# Continuously listen for incoming connections
while True:
    try:
        # Accept a connection
        c, addr = s.accept()
        print('Connection established:', addr)
        
        # Receive data from the client
        data = c.recv(8192).decode()
        
        # Parse the received JSON message
        data = json.loads(data)
        
        # Process the message based on its type
        if isinstance(data, dict):
            print('Received message from client:', data)
            vpk = bytes(data['voter_public_key'], 'utf-8')
            ls = [vpk.decode('unicode-escape').encode('ISO-8859-1'), data['data'], data['key']]
            
            # Write the extracted data to a CSV file
            with open('temp/votefile.csv', 'a', newline="") as votefile:
                writer = csv.writer(votefile)
                writer.writerow(ls)
            
            # Send acknowledgment back to the client
            c.send(bytes('ACKD', 'utf-8'))
        else:
            print('Received message from client:', data)
            
            # Write the message directly to a CSV file
            with open('temp/result.csv', 'w', newline="") as votefile:
                writer = csv.writer(votefile)
                writer.writerow(data)

    except BrokenPipeError:
        # Handle broken pipe errors (if any)
        pass
