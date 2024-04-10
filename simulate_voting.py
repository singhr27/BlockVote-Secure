#This is the main file for the voting simulation. 
#It contains the code for the blockchain, the voting process, and the Flask web application.
#The blockchain is used to store the votes and the results of the election.
#The voting process is simulated by the Flask web application, where voters can sign up, vote, and view the results.
#The blockchain is updated with the votes as they are cast, and the results are displayed in real-time.
#The blockchain is also used to verify the integrity of the votes and the results.


from hashlib import sha256
from hashlib import *
from time import sleep, time
import time
from flask import Flask, request, render_template, redirect
from hashlib import sha256
from Crypto.Cipher import AES
from Crypto import Random
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Util.Padding import pad, unpad
import csv
import pickle
import json
import threading as thr
import shutil
from Crypto.PublicKey import RSA
import rsa as rsa
import qrcode
import glob
import matplotlib.pyplot as plt; 
plt.rcdefaults()
import numpy as np
import pickle as pk
import os,glob
import base64
import socket


#--global variables
BLOCK_SIZE = 16
DIFFICULTY = 3
BLOCK_TIME_LIMIT = 20
PROJECT_PATH = os.path.dirname(os.path.abspath(__file__))

registered_voters = []
hidden_voter_id = ''
voter_keys = {}

#---------------class definitions-----------------#

#--class for vote
#--each vote object will have the following attributes:
#--hidden_voter_id: the hashed voter id
#--candidate: the candidate id
#--voter_public_key: the voter's public key
#--time: the time of vote
#--vote_data: the data of the vote
#--count: the total number of votes
#--the class will have the following methods:
#--get_voter_public_key: returns the voter's public key
#--encrypt_vote: encrypts the vote data and returns the encrypted data
#--inc_vote_count: increments the vote count
#--get_vote_count: returns the vote count
class Vote:
    count = 0

    def __init__(self, hidden_voter_id, candidate_id, voter_public_key):
        self.hidden_voter_id = hidden_voter_id
        self.candidate = candidate_id
        self.voter_public_key = voter_public_key
        self.time = time.time()
        self.vote_data = [self.hidden_voter_id, self.candidate, self.time]

    def get_voter_public_key(self):
        return pickle.dumps(self.voter_public_key.exportKey())

    def encrypt_vote(self):
        voter_keys['aeskey']= get_private_key('Abhi-Ravi') #default until voter id is not given
        if 'sk' in voter_keys:
            self.vote_data.append(rsa.create_signature(voter_keys['sk'], bytes(sha256(str('---'.join(str(x) for x in self.vote_data)).encode('utf-8')).hexdigest(),'utf-8')))
            voter_pk = self.get_voter_public_key()
            return [str(voter_pk)[2:-1], str(encrypt('***'.join(str(i) for i in self.vote_data), voter_keys['aeskey']))[2:-1], str(rsa.encrypt_rsa(Blockchain.admin_pub, voter_keys['aeskey']))[2:-1]]
        else:
            voter_keys['sk'], voter_keys['pk'] = rsa.generate_rsa_keys()
            self.vote_data.append(rsa.create_signature(voter_keys['sk'], bytes(sha256(str('---'.join(str(x) for x in self.vote_data)).encode('utf-8')).hexdigest(),'utf-8')))
            voter_pk = self.get_voter_public_key()
            return [str(voter_pk)[2:-1], str(encrypt('***'.join(str(i) for i in self.vote_data), voter_keys['aeskey']))[2:-1], str(rsa.encrypt_rsa(Blockchain.admin_pub, voter_keys['aeskey']))[2:-1]]
            
    @classmethod
    def inc_vote_count(cls):
        cls.count += 1

    @classmethod
    def get_vote_count(cls):
        return cls.count



#--class for blockchain
#--the blockchain will have the following attributes:
#--chain: a list to store the blocks
#--admin_priv: the admin's private key
#--admin_pub: the admin's public key
#--the blockchain will have the following methods:
#--genesis: returns the genesis block
#--add_genesis: adds the genesis block to the chain
#--display: displays the blockchain
#--update_vote_pool: updates the vote pool
#--is_vote_pool_empty: checks if the vote pool is empty
#--verify_chain: verifies the blockchain
class Blockchain:
    chain = []
    admin_priv, admin_pub = rsa.generate_rsa_keys()

    def __init__(self):
        self.add_genesis()
        print('Blockchain initialized')
    #
    #static methods
    @staticmethod
    def genesis():
        gen = Block(0,"Please reinvent the democracy.",0, sha256(str("Please reinvent the democracy.").encode('utf-8')).hexdigest(), DIFFICULTY, time.time(),'',0,'Errrrrorrr')
        return gen

    @staticmethod
    def add_genesis(): 
        genesis_block = Blockchain.genesis()
        genesis_block.nonce = genesis_block.pow()
        genesis_block.hash = genesis_block.calc_hash()
        Blockchain.chain.append(genesis_block)
        # we will store the genesis block in a file
        with open('temp/Blockchain.dat', 'ab') as gen_file:
            #serialize the block object
            pickle.dump(genesis_block, gen_file)
        print("Genesis block added")

    @staticmethod
    def display():
        try:
            # with open('temp/blockchain.dat', 'rb') as block_file:
                for block in Blockchain.chain:
                    # data = pickle.load(block))
                    print("\nBlock Height: ", block.height)
                    print("Merkle root: ", block.merkle)
                    print("Number of votes: ", block.number_of_votes)
                    print("Difficulty: ", block.DIFFICULTY)
                    print("Time stamp: ", block.time_stamp)
                    print("Previous hash: ", block.prev_hash)
                    print("Block Hash: ", block.hash)
                    print("Nonce: ", block.nonce )
                    print("Data in block: ", block.data, '\n\t\t|\n\t\t|')
        except FileNotFoundError:
            print("\n.\n.\n.\n<<<File not found!!>>>")

    @staticmethod
    def update_vote_pool():
        try:
            with open('temp/votefile.csv', 'w+') as vote_file:
                pass
        except Exception as e:
            print("Some error occurred: ", e)
        return "Done"


    @classmethod
    def verify_chain(cls):
        index, conclusion = sync_blocks(cls.chain)
        if not conclusion:
            error_msg = "+EROR-----------------------------------------+\n|                                         |\n| Somebody messed up at Block number - {}  |\n|                                         |\n+-----------------------------------------+".format(index)
            raise Exception(error_msg)
        return True


    def is_vote_pool_empty(self):
        my_path = os.path.join(PROJECT_PATH, 'temp', 'votefile.csv')
        if os.path.isfile(os.path.expanduser(my_path)) and os.stat(os.path.expanduser(my_path)).st_size == 0:
            return True
        return False


#--class for block
#--each block object will have the following attributes:
#--height: the height of the block
#--data: the data of the block
#--number_of_votes: the number of votes in the block
#--merkle: the merkle root of the block
#--DIFFICULTY: the difficulty level of the block
#--time_stamp: the time of the block
#--prev_hash: the hash of the previous block
#--nonce: the nonce of the block
#--hash: the hash of the block
#--the block will have the following methods:
#--pow: the proof of work method
class Block:
    def __init__(self, height=0, data='WARNING = SOME ERROR OCCURRED', votes=0, merkle='0', DIFFICULTY=0, time_stamp=0, prev_hash='0', pow=0, hash_='ERROR'):
        self.height = height
        self.data = data
        self.number_of_votes = votes
        self.merkle = merkle
        self.DIFFICULTY = DIFFICULTY
        self.time_stamp = time_stamp
        self.prev_hash = prev_hash
        self.nonce = pow
        self.hash = hash_

    def pow(self, zero=DIFFICULTY):
        self.nonce = 0
        while self.calc_hash()[:zero] != '0' * zero:
            self.nonce += 1
        return self.nonce

    def calc_hash(self):
        return sha256((str(str(self.data) + str(self.nonce) + str(self.time_stamp) + str(self.prev_hash))).encode('utf-8')).hexdigest()

    @staticmethod
    def load_vote():
        vote_list = []
        vote_count = 0

        try:
            with open('temp/votefile.csv', mode='r') as vote_pool:
                csv_reader = csv.reader(vote_pool)
                for row in csv_reader:
                    vote_list.append({'Voter Public Key': row[0], 'Vote Data': row[1], 'Key': row[2]})
                    vote_count += 1
            return vote_list, vote_count
        except (IOError, IndexError):
            pass
        finally:
            print("Data loaded in block")
            print("Updating unconfirmed vote pool...")
            print(Blockchain.update_vote_pool())

    def merkle_root(self):
        return 'I am Root'

    def mine_block(self):
        self.height = len(Blockchain.chain)
        result = self.load_vote()
        if result is None:
            self.data = ""
            self.number_of_votes = 0
        else:
            self.data, self.number_of_votes = result
        self.merkle = self.merkle_root()
        self.DIFFICULTY = DIFFICULTY
        self.time_stamp = time.time()
        self.prev_hash = Blockchain.chain[-1].calc_hash()
        self.nonce = self.pow()
        self.hash = self.calc_hash()
        Blockchain.chain.append(self)
        return self


#------------------------------FLASK APP--------------------------------#

app = Flask(__name__)



@app.route('/')
#--the login page, home page
def home():
    return render_template('home.html')

#--global variables for flask web application

voterlist = [] #--to keep duplicates out
invisiblevoter = '' #--global variable used to hide voter's identity
voterkeys = {} #--voter's keys stored temporarily in this dictionary


@app.route('/signup', methods = ['POST'])
#--voter signup page
def votersignup():
    voterid = request.form['voterid']
    pin = request.form['pin']
    voterkeys['pin'] = pin
    voterkeys['aeskey'] = get_private_key(voterid)
    print( "hello")
    print (voterid, pin, voterkeys['aeskey'])
    global invisiblevoter

    """
    #####-------ZERO KNOWLEDGE PROOF-------########
    <<<<<<implemented by hashing the voterID appended by PIN>>>>>>
    """
    invisiblevoter = str(sha256((str(voterid)+str(pin)).encode('utf-8')).hexdigest())

#--Voter re-signup check
    if voterid not in voterlist:
        voterlist.append(voterid)

#--If condition satisfied, voter can be allowed to vote
#--his data will be written on the database
        with open('temp/VoterID_Database.txt', 'a') as voterdata:
            voterdata.write(str(sha256(str(voterid).encode('utf-8')).hexdigest()))
            voterdata.write("\n")
        return render_template('vote.html')
#--If not, the voter will be redirected to a different page.
    else:
        return render_template('oops.html')

#--voting page
@app.route('/vote', methods = ['POST'])
def voter():
#--the voter is eligible if reached this page.
#--hence his own keys will be generated.
    voterkeys['sk'],voterkeys['pk'] = rsa.generate_rsa_keys()         #--voter public/private key pair generated here
    choice = request.form['candidate']


#--vote object created
    v1 = Vote(invisiblevoter, int(choice), voterkeys['pk'])
    print(v1.vote_data)
    Vote.inc_vote_count()
    print(Vote.get_vote_count())


#--votedata digitally signed and encrypted and sent to the temporary pool
    with open('temp/votefile.csv','a',newline="") as votefile:
        writer = csv.writer(votefile)
        encvotedata = v1.encrypt_vote()
        writer.writerow(encvotedata)

#--and broadcasted to other peers on the network
    send_vote_data_to_peer('127.0.0.1',9999,encvotedata)
    # This method mines new blocks after generation of every 2 votes
    # Uncomment this method and comment the 'mine_blocktimer()' method 
    # to switch to 'vote count block mining' method - where block will be mined after 2 votes are generated and not on regular time intervals.
    if Vote.count%2==0:
        blockx = Block().mine_block()
        with open('temp/blockchain.dat','ab') as blockfile:
            pickle._dump(blockx,blockfile)
        print("block added")

    pass

    
    # Now the QR code containing the information about your PIN
    # and private key is printed on the thank you page.

    return redirect('/thanks')


#--thank you page
@app.route('/thanks', methods = ['GET'])
def thank():
    #--thank you page
    qrname = generate_QR(voterkeys['sk'],voterkeys['pin'])
    return render_template('thanks.html', qrcode = qrname)


#--delete the folder containing the application data and make a fresh one by the same name
def clear_garbage():
    folder = PROJECT_PATH + '/temp'
    shutil.rmtree(os.path.expanduser(folder))
    if not os.path.exists(os.path.expanduser(folder)):
        os.makedirs(os.path.expanduser(folder))



#Results - NOT WORKING RIGHT NOW
# def get_result(admin_private_key):
#     vote_list = []
#     with open('temp/blockchain.dat', 'rb') as block_file:
#         genesis_block = pickle.load(block_file)
#         while True:
#             try:
#                 block = pickle.load(block_file)
#                 vote_list.extend(block.data)
#             except EOFError:
#                 break
#     results = []
#     for vote in vote_list:
#         #vote_key = bytes(vote['Key'], 'utf-8')
#         print(vote)
#         vote_key = bytes(vote.get('Key', ''), 'utf-8')
        
        
#         aes_key = rsa.decrypt_rsa(admin_private_key, vote_key)
#         unlocked_data = decrypt(bytes(vote['Vote Data'], 'utf-8'), aes_key)
#         unlocked_data = str(unlocked_data)[2:-1]
#         vote_data = unlocked_data.split('***')
#         vote_data[1] = int(vote_data[1])
#         results.append(vote_data[1])

#     return results

#--timer for mining blocks
#--the timer will mine a block after every 15 seconds
#--the block will be added to the blockchain
#--the timer will repeat
def inline_timer(bt):
    while True:
        sleep(bt)        #--global variable
        #--sleep for 15 seconds --> mine a block --> repeat
        blockx = Block().mine_block()
        with open('temp/blockchain.dat','ab') as blockfile:
            pickle._dump(blockx,blockfile)
        print("block added")


#--timer for mining blocks
def mine_block_timer():
    timer_thread = thr.Thread(target=inline_timer, args=(BLOCK_TIME_LIMIT,))
    timer_thread.start()

#--send vote data to peer
def send_vote_data_to_peer(host, port, data_list):
    c = socket.socket()
    c.connect((host, port))
    data = jsonify_vote_data(data_list)
    c.send(bytes(data, 'utf-8'))
    if not c.recv(8192).decode() == 'ACKD':
        pass

#--receive vote data from peer
def jsonify_vote_data(vote_data_list):
    json_dict = {'voter_public_key': vote_data_list[0], 'data': vote_data_list[1], 'key': vote_data_list[2]}
    return json.dumps(json_dict)

# --------------------AES Encryption-------------------
def get_private_key(password):  
    password_hash = sha256(password.encode('utf-8')).digest()  # Changed to digest()
    salt = b"this is a salt and the m0re c0mplex th!s wi11 be, the m0re d!44icult w1!! b3 the K37"
    # Password Based Key Derivation Function 2 (PBKDF2)
    key = PBKDF2(password_hash, salt, dkLen=32, count=1000)  # Changed to dkLen and count parameters
    return key

def encrypt(raw, private_key):
    # Convert string input to bytes
    raw_bytes = raw.encode('utf-8')

    # Pad the input if necessary
    padded_raw = pad(raw_bytes, BLOCK_SIZE)

    # Generate a random IV
    iv = Random.new().read(BLOCK_SIZE)

    # Create AES cipher object
    cipher = AES.new(private_key, AES.MODE_CBC, iv)

    # Encrypt the data
    encrypted = cipher.encrypt(padded_raw)

    # Combine IV and encrypted data and encode it using base64
    encrypted_data = base64.b64encode(iv + encrypted)

    return encrypted_data

def decrypt(enc, private_key):
    enc = base64.b64decode(enc)
    iv = enc[:BLOCK_SIZE]
    cipher = AES.new(private_key, AES.MODE_CBC, iv)
    return unpad(cipher.decrypt(enc[BLOCK_SIZE:]), BLOCK_SIZE)  # Changed to unpad() with BLOCK_SIZE parameter


#--show the performance of the candidates -NOT WORKING RIGHT NOW
# def show_performance(performance_data):
#     parties = ('NDP', 'Liberal', 'PPC')  
#     y_positions = np.arange(len(parties))  

#     plt.bar(y_positions, performance_data, align='center', alpha=1)
#     plt.xticks(y_positions, parties)
#     plt.ylabel('Votes')
#     plt.title('Elections Result')

#     plt.show()

# QR Code
def generate_QR(data, pin):
    key = sk_to_data(data, pin)
    qr = qrcode.QRCode(version=1, error_correction=qrcode.constants.ERROR_CORRECT_L, box_size=10, border=4)
    qr.add_data(key)
    qr.make(fit=True)

    img = qr.make_image(fill_color="black", back_color="white")
    cleardata()
    qr_filename = "qr" + str(int(time.time())) + ".png"  
    img.save('static/' + qr_filename)
    return qr_filename

#--clear the data
def cleardata():
    for filename in glob.glob("static/qr*"):
        os.remove(filename)

# Convert the private key to data
def sk_to_data(private_key, pin):  # Changed variable name
    key = private_key.exportKey().decode()

    print(key)
    ls = [str(pin), key]
    data = '****'.join(element for element in ls)
    return data

#sync blocks
def sync_blocks(blockchain):
    for i in range(1, len(blockchain)):
        # Introduce a delay of 1 second between each iteration
        time.sleep(1)
        if blockchain[i].prevHash == blockchain[i - 1].calcHash():
            continue
        else:
            return i, False

    return 0, True

#veirfy block
def verify_block(block):
    check_1 = sha256((str(str(block.data) + str(block.nonce) + str(block.timeStamp) + str(block.prevHash))).encode('utf-8')).hexdigest()
    # Introduce a delay of 5 seconds
    time.sleep(5)
    check_2 = sha256((str(str(block.data) + str(block.nonce) + str(block.timeStamp) + str(block.prevHash))).encode('utf-8')).hexdigest()

    return check_1 == check_2


#--main function
if __name__ == '__main__':
    cleardata()
    mine_block_timer()
    EVoting = Blockchain()
    with open('temp/VoterID_Database.txt', 'w+') as f:
        pass
    
    app.run(port=5000)

    if not EVoting.is_vote_pool_empty():
        last_block = Block().mine_block()
        with open('temp/blockchain.dat','ab') as blockfile:
            pickle._dump(last_block, blockfile)
        print("Block added")

    Blockchain.display()
    print("\n\n\n", end='')
    print("Total number of votes:", Vote.get_vote_count())


    # my_result = get_result(EVoting.admin_priv) #--NOT WORKING RIGHT NOW
    # print(my_result)
    # with open('temp/result.csv', 'r', newline="") as votefile:
    #     reader = csv.reader(votefile)
    #     reader = [int(x) for x in list(reader)[0]]
    # my_result.extend(reader)
    # print(my_result)
    # bar = []
    # bar.append(my_result.count(1))
    # bar.append(my_result.count(2))
    # bar.append(my_result.count(3))
    # show_performance(bar)