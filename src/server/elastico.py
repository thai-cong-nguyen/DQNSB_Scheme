import threading
import socket
from Cryptodome.Signature import PKCS1_v1_5
from Cryptodome.PublicKey import RSA
from Cryptodome.Hash import SHA256
from secrets import SystemRandom
import logging

global identity_node_map, r, n, s, c, D, fin_num

# n - number of processors
n =  150 # 150
# s - where 2^s is the number of committees
s = 4
# c - size of committee
c = 2
# D - difficulty level , leading bits of PoW must have D 0's (keep w.r.t to hex)
D = 1 
# r - number of bits in random string
r = 5
# fin_num - final committee id
fin_num = 0
# identity_node_map - mapping of identity object to Elastico node
identity_node_map = dict()
# commitment_set - set of commitment S
commitment_set = set()
# ledger - ledger is the database that contains the set of blocks where each block comes after an epoch
ledger = []
# network_participating_nodes - list of nodes those are the part of some committee
network_participating_nodes = []
# network_nodes - list of all nodes 
network_nodes = []

# State representing node state
ELASTICO_STATES = {"NONE": 0, "PoW Computed": 1, "Formed Identity" : 2,"Formed Committee": 3, "RunAsDirectory": 4 ,"Receiving Committee Members" : 5,"Committee full" : 6 , "PBFT Finished" : 7, "Intra Consensus Result Sent to Final" : 8, "Final Committee in PBFT" : 9, "FinalBlockSent" : 10, "FinalBlockReceived" : 11, "RunAsDirectory after-TxnReceived" : 12, "RunAsDirectory after-TxnMulticast" : 13, "Final PBFT Start" : 14, "Merged Consensus Data" : 15, "PBFT Finished-FinalCommittee" : 16 , "CommitmentSentToFinal" : 17, "BroadcastedR" : 18, "ReceivedR" :  19, "FinalBlockSentToClient" : 20}

def consistency_protocol():
    """
		Agrees on a single set of Hash values(S)
		presently selecting random c hash of Ris from the total set of commitments
	"""
    global network_nodes, commitment_set
    for node in network_nodes:
        if node.is_final_member():
            if len(node.commitments) <= c//2:
                input("insufficientCommitments")
                return False, "insufficientCommitments"
    
    # ToDo: Discuss with sir about intersection.
    if len(commitment_set) == 0:
        flag = True
        for node in network_nodes:
            if node.is_final_member():
                if flag and len(commitment_set) == 0:
                    flag = False
                    commitment_set = node.commitments
                else:
                    commitment_set = commitment_set.intersection(node.commitments)
    return True, commitment_set

def random_generation(size=32):
    return SystemRandom().getrandbits(size)

def broadcast_to_network(data, type_action):
    """
        Broadcast data to the whole network
    """
    global identity_node_map
    print("---Broadcast to network---")
    message = {"type": type_action, "data": data}
    # directly accessing of elastico objects should be removed
    for node in network_nodes:
        node.receive(message)

def multi_cast_committee(committee_list, identity, txns):
    """
		each node getting views of its committee members from directory members
	"""

    print("---multicast committee list to committee members---")

    # print(len(commList), commList)
    final_committee_members = committee_list[fin_num]
    for committee_id in committee_list:
        committee_members = committee_list[committee_id]
        for member_id in committee_members:
            # union of committe members views
            data = {"committee members" : committee_members , "final Committee members"  : final_committee_members , "txns" : txns[committee_id] ,"identity" : identity}
            msg = {"data" : data , "type" : "committee members views"}
            member_id.send(msg)

class Identity:
    """
        Identity of nodes 
        - nonce is come from Proof of Work
    """
    def __init__(self, IP, PK, committee_id, PoW, epoch_randomness) -> None:
        #  self.id_proof = IDProof(
        #     IP, 
        #     PK, 
        #     committee_id,
        #     PoW,
        #     epoch_randomness,
        #     False # DEFAULT is False - not a part of network
        # )
        self.IP = IP
        self.PK = PK
        self.committee_id = committee_id
        self.PoW = PoW
        self.epoch_randomness = epoch_randomness
        self.partOfNtw = False

    def __str__(self) -> str:
        return "\nIdentity - IP: {} - PK: {} - committee_id: {} - PoW: {} - epoch_randomness: {} - part_of_network: {}".format(self.IP, self.PK, self.committee_id, self.PoW, self.epoch_randomness, self.partOfNtw)
    
    def is_equal(self, identity):
        return self.IP == identity.IP and self.PK == identity.PK and self.CommitteeId == identity.CommitteeId and self.Nonce == identity.Nonce and self.EpochRandomness == identity.EpochRandomness and self.PartOfNtw == identity.PartOfNtw
    
    def send(self, message):
        print("--send to node--")
        global identity_node_map
        node = identity_node_map[self]
        node.lock.acquire()
        response = node.receive(message)
        node.lock.release()
        return response
    
class Elastico:
    def __init__(self) -> None:
        print("---Constructor of elastico class---")
        self.IP = self.get_IP()
        self.key = self.get_key()
        self.PoW = {"hash": "", "set_of_Rs": "", "nonce": 0}
        self.lock = threading.Lock()
        self.cur_directory = []
        self.identity = ""
        self.committee_id = ""
        self.committee_list = dict()
        self.committee_members = set()
        self.is_directory = False
        self.is_final = False
        self.epoch_randomness = self.init_epoch_randomness()
        self.Ri = ""
        self.commitments = set()
        self.txn_block = set()
        self.set_of_Rs = set()
        self.new_set_of_Rs = set()
        self.committee_consensus_data = dict()
        self.final_block_by_final_committee = dict()
        self.state = ELASTICO_STATES['NONE']
        self.merged_block = []
        self.final_block = {"sent": False, "finalBlock": []}
        self.R_commitment_set = ""
        self.new_R_commitment_set = ""
        self.final_committee_members = set()
        # only if this node is the member of final committee
        self.consensus_msg_count = dict()
        # only if this is the member of the directory committee 
        self.txn = dict()

    def reset(self):
        """ 
            reset some of the elastic attributes
        """
        self.IP = self.get_IP()

    def init_epoch_randomness(self):
        """
            initialize r-bit epoch randomness string
        """
        print("---initial epoch randomness for a node---")
        random_num = random_generation(r)
        return ("{:0" + str(r) +  "b}").format(random_num)
    
    def get_IP(self):
        """
            get IP address of each node 
        """
        print("---get IP address---")
        ip=""
        for i in range(4):
            ip += str(random_generation(8))
            ip += "."
        ip = ip[:-1]
        return ip
    
    def get_key(self):
        """
            get the public private key pair of each node
        """
        print("---get public pvt key pair---")
        key = RSA.generate(2048)
        return key
    
    def compute_PoW(self):
        print("---PoW computation started---")
        if self.state == ELASTICO_STATES['NONE']:
            PK = self.key.public_key().export_key().decode()
            IP = self.IP
            # if this is the first epoch, random_set_R is empty
            # otherwise random_set_R will be any c/2 + 1 random strings Ri that node receives from the previous epoch
            random_set_R = set()
            if len(self.set_of_Rs) > 0:
                self.epoch_randomness, random_set_R = self.xor_R()

            digest = SHA256.new()
            digest.update(IP.encode())
            digest.update(PK.encode())
            digest.update(self.epoch_randomness.encode())
            digest.update(str(self.PoW["nonce"]).encode())
            hash_value = digest.hexdigest()
            if hash_value.startswith('0' * D):
                nonce = self.PoW["nonce"]
                self.PoW = {"hash": hash_value, "set_of_Rs": random_set_R, "nonce": nonce}
                print("---PoW computation end---")
                self.state = ELASTICO_STATES["PoW Computed"]
                return hash_value
            self.PoW["nonce"] += 1

    def notify_final_committee(self):
        """
            notify the nodes of the final committee that they are the final committee nodes
        """

        final_committee_list = self.committee_list[fin_num]
        for final_members in final_committee_list:
            data = {"identity": self.identity}
            message = {"data": data, "type": "Notify final members"}
            final_members.send(message)

    def get_committee_id(self, PoW):
        """
            last s-bits of PoW["hash"] as Identity
        """
        binary_digest = ''
        for hash_digest in PoW:
            binary_digest += "{:04b}".format(int(hash_digest, 16))
        identity = binary_digest[-s:]
        return int(identity, 2)
    
    def form_identity(self):
        """
            identity formation for a node
            Identity = IDProof(public key, ip, committee id, PoW, nonce, epoch randomness)
        """
        if self.state == ELASTICO_STATES["PoW Computed"]: 
            global identity_node_map
            print("---form identity---")
            # export public key
            PK = self.key.public_key().export_key().decode()
            # set the committee id acc to PoW solution
            self.committee_id = self.get_committee_id(PoW=self.PoW["hash"])
            self.identity = Identity(IP=self.IP, PK=PK, committee_id=self.committee_id, PoW=self.PoW, epoch_randomness=self.epoch_randomness)
            # mapped identity object to the elastico object
            identity_node_map[self.identity] = self
            self.state = ELASTICO_STATES["Formed Identity"]
            return self.identity
        
    def is_own_identity(self, identity):
        """
            Checking if the identity is the Elastico node's identity or not
        """
        if self.identity == "":
            self.form_identity()
        return self.identity.is_equal(identity=identity)
    
    def form_committee(self):
        """
            Creates directory committee if not created yet otherwise informs all the directory members
        """
        if len(self.cur_directory) < c:
            self.is_directory = True
            print("---not seen c members yet, so broadcast to ntw---")
            # do all broadcast asynchronously
            broadcast_to_network(data=self.identity, type_action="directoryMember")
            self.state = ELASTICO_STATES["RunAsDirectory"]
        else:
            print("---seen c members---")
            # track previous state before adding in committee
            prevState = self.state
            self.send_to_directory()
            # check state assignment order
            if prevState == ELASTICO_STATES["Formed Identity"] and self.state == ELASTICO_STATES["Receiving Committee Members"]:
                message = {"data": self.identity, "type": "Committee full"}
                broadcast_to_network(data=message["data"], type_action=message["type"])
            elif self.state != ELASTICO_STATES["Receiving Committee Members"]:
                self.state = ELASTICO_STATES["Formed Committee"]
                # broadcast committee full state notification to all nodes when the present state is "Received Committee members"

    def send_to_directory(self):
        """
            Send about new nodes to directory committee members
        """
        # Add the new processor in particular committee list of directory committee nodes
        for nodeId in self.cur_directory:
            print("---Send to directory---")
            message = {"data": self.identity, "type": "newNode"}
            nodeId.send(message)

    def check_committee_full(self):
        """
            directory member checks whether the committees are full or not
        """
        committee_list = self.committee_list
        flag = 0
        for identity in range(pow(2, s)):
            if identity not in committee_list or len(committee_list[identity]) < c:
                flag = 1
                break
        if flag == 0:
            print("----------committees full----------------")
            # Send committee_list[identity] to members of committee_list[identity]
            if self.state == ELASTICO_STATES["RunAsDirectory"]:
				# directory member has not yet received the epochTxn
                print("directory member has not yet received the epochTxn")
                input()
                pass
            if self.state == ELASTICO_STATES["RunAsDirectory after-TxnReceived"]:
                multi_cast_committee(committee_list=committee_list, identity=self.identity, txns=self.txn)
                self.state = ELASTICO_STATES["RunAsDirectory after-TxnMulticast"]
                self.notify_final_committee()
                # ToDo: transition of state to committee full 

    def receive(self, message):
        """
            method to recieve messages for a node as per the type of a message
        """
        if message["type"] == "directoryMember":
            #  verify the PoW of the sender
            identity = message["data"]
            if self.verify_PoW(identity):
                if len(self.cur_directory) < c:
                    self.cur_directory.append(identity)
            else:
                print("$$$$$$$ PoW not valid $$$$$$")
        # new node is added to the corresponding committee list of committee list has less than c members
        elif message["type"] == "newNode" and self.is_directory:
            identity = message["data"]
            if self.verify_PoW(identity):
                committee_id = identity.committee_id
                if committee_id not in self.committee_list:
                    self.committee_list[committee_id] = [identity]
                elif len(self.committee_list[committee_id]) <= c:
                    self.committee_list[committee_id].append(identity)
                    # Once each committee contains at least c identities each, directory members multicast the committee list to each committee member
                    if len(self.committee_list[committee_id]) == c:
                        self.check_committee_full()
            else:
                print("$$$$$$$ PoW not valid 22222 $$$$$$")
        
        # union of committee members view
        elif message["type"] == "committee members views" and self.verify_PoW(message["data"]["identity"]) and not self.is_directory:
            # data = {
                # "committee members": commMembers , 
                # "final Committee members": finalCommitteeMembers , 
                # "txns" : self.txn[committee_id] ,
                # "identity" : self.identity
            # }
            committee_members = message["data"]["committee members"]
            final_members = message["data"]["final Committee members"]
            self.txn_block |= set(message["data"]["txns"])
            self.committee_members |= set(committee_members)
            self.final_committee_members |= set(final_members)
            self.state = ELASTICO_STATES["Receiving Committee Members"]
            print("commMembers for committee id - " , self.committee_id, "is :-", self.committee_members)

        elif message["type"] == "Committee full" and self.verify_PoW(message["data"]):
            if self.state == ELASTICO_STATES["Receiving Committee Members"]:
                self.state = ELASTICO_STATES["Committee full"]

        # receiving H(Ri) by final committe members
        elif message["type"] == "hash" and self.is_final_member():
            data = message["data"]
            identity = data["identity"]
            if self.verify_PoW(identity):
                self.commitments.add(data["Hash_Ri"])

        elif message["type"] == "RandomStringBroadcast":
            data = message["data"]
            identity = data["identity"]
            if self.verify_PoW(identity):
                Ri = data["Ri"]
                HashRi = self.hexdigest(Ri)
                if HashRi in self.newRcommitmentSet:
                    self.newset_of_Rs.add(Ri)
                    if len(self.newset_of_Rs) >= c//2 + 1:
                        self.state = ELASTICO_STATES["ReceivedR"]

        elif message["type"] == "finalTxnBlock":
            data = message["data"]
            # data = {
            # "commitmentSet" : S, 
            # "signature" : self.sign(S) , 
            # "finalTxnBlock" : self.txn_block
            # }
            identity = data["identity"]
            if self.verify_PoW(identity):
                sign = data["signature"]
                received_commitment_set = data["commitmentSet"]
                PK = identity.PK
                finalTxnBlock = data["finalTxnBlock"]
                finalTxnBlock_signature = data["finalTxnBlock_signature"]
                if self.verify_sign(sign, received_commitment_set, PK) and self.verify_sign(finalTxnBlock_signature, finalTxnBlock, PK):
                    if str(finalTxnBlock) not in self.finalBlockbyFinalCommittee:
                        self.finalBlockbyFinalCommittee[str(finalTxnBlock)] = set()
                    self.finalBlockbyFinalCommittee[str(finalTxnBlock)].add(finalTxnBlock_signature)
                    if len(self.finalBlockbyFinalCommittee[str(finalTxnBlock)]) >= c//2 + 1:
                        # for final members, their state is updated only when they have also sent the finalblock
                        if self.is_final_member():
                            if self.finalBlock["sent"]:
                                self.state = ELASTICO_STATES["FinalBlockReceived"]
                            pass
                        else:
                            self.state = ELASTICO_STATES["FinalBlockReceived"]
                    # ToDo : Check this, It is overwritten here or need to be union of commitments
                    if self.newRcommitmentSet == "":
                        self.newRcommitmentSet = set()
                    self.newRcommitmentSet |= received_commitment_set

                else:
                    print("Signature invalid")
                    input()
            else:
                print("PoW not valid")
                input()

        elif message["type"] == "getCommitteeMembers":
            if not self.is_directory:
                return False , set()
            data = message["data"]
            identity = data["identity"]
            if self.verify_PoW(identity):
                committeeid = data["committee_id"]
                print("final comid :-" , committeeid)
                return True, self.committee_list[committeeid]

        # final committee member receives the final set of txns along with the signature from the node
        elif message["type"] == "intraCommitteeBlock" and self.is_final_member():
            data = message["data"]
            identity = data["identity"]
            print("txnBlock : - " , data["txnBlock"])
            print("commid - " , identity.committee_id)
            if self.verify_PoW(identity):
                # data = {"txnBlock" = self.txn_block , "sign" : self.sign(self.txn_block), "identity" : self.identity}
                if self.verify_sign(data["sign"], data["txnBlock"] , identity.PK):
                    if identity.committee_id not in self.CommitteeConsensusData:
                        self.CommitteeConsensusData[identity.committee_id] = dict()
                    # add signatures for the txn block 
                    if str(data["txnBlock"]) not in self.CommitteeConsensusData[identity.committee_id]:
                        self.CommitteeConsensusData[identity.committee_id][ str(data["txnBlock"]) ] = set()
                    self.CommitteeConsensusData[identity.committee_id][ str(data["txnBlock"]) ].add( data["sign"] )
                    if identity.committee_id not in self.ConsensusMsgCount:
                        self.ConsensusMsgCount[identity.committee_id	] = 1
                    else:	
                        self.ConsensusMsgCount[identity.committee_id] += 1

        elif message["type"] == "request committee list from directory member":
            if not self.is_directory:
                return False , dict()
            else:
                commList = self.committee_list
                return True , commList

        elif message["type"] == "command to run pbft":
            if not self.is_directory:
                self.run_PBFT(self.txn_block, message["data"]["instance"])

        elif message["type"] == "command to run pbft by final committee":
            if self.is_final_member():
                self.run_PBFT(self.mergedBlock, message["data"]["instance"])


        elif message["type"] == "send txn set and sign to final committee":
            if not self.is_directory:
                self.send_to_final()

        elif message["type"] == "verify and merge intra consensus data":
            if self.is_final_member():
                self.verify_and_merge_consensus_data()	

        elif message["type"] == "send commitments of Ris":
            if self.is_final_member():
                self.send_commitment()

        elif message["type"] == "broadcast final set of txns to the ntw":
            if self.is_final_member():
                self.BroadcastFinalTxn()

        elif message["type"] == "notify final member":
            if self.verify_PoW(message["data"]["identity"]):
                self.is_final = True

        elif message["type"] == "Broadcast Ri":
            if self.is_final_member():
                self.broadcast_R()

        elif message["type"] == "append to ledger":
            if not self.is_directory and len(self.committee_Members) == c:
                response = []
                for txnBlock in self.finalBlockbyFinalCommittee:
                    if len(self.finalBlockbyFinalCommittee[txnBlock]) >= c//2 + 1:
                        response.append(txnBlock)
                return response		

        elif message["type"] == "reset-all" and self.verify_PoW(message["data"]):
            # reset the elastico node
            self.reset()

    def verify_and_merge_consensus_data(self):
        """
            each final committee member validates that the values received from the committees are signed by 
            atleast c/2 + 1 members of the proper committee and takes the ordered set union of all the inputs
        """
        print("--verify And Merge--")
        for committeeid in range(pow(2,s)):
            print("comm id : -" , committeeid)
            if committeeid in self.CommitteeConsensusData:
                for txnBlock in self.CommitteeConsensusData[committeeid]:
                    if len(self.CommitteeConsensusData[committeeid][txnBlock]) >= c//2 + 1:
                        print(type(txnBlock) , txnBlock)
                        # input()
                        try:
                            # ToDo: Check where is empty block coming from
                            if len(txnBlock) > 0:
                                set_of_txns = eval(txnBlock)
                        except Exception as e:
                            print("excepton:" , txnBlock , "  ", len(txnBlock), " ", type(txnBlock))
                            raise e
                        self.mergedBlock.extend(set_of_txns)
        if len(self.mergedBlock) > 0:
            self.state = ELASTICO_STATES["Merged Consensus Data"]
            print(self.mergedBlock)
            input("Check merged block above!")

    def run_PBFT(self , txn_block, instance):
        """
            Runs a Pbft instance for the intra-committee consensus
        """
        txn_set = set()
        for txn in txn_block:
            txn_set.add(txn)
        if instance == "final committee consensus":
            self.final_block["finalBlock"] = txn_set
            self.state = ELASTICO_STATES["PBFT Finished-FinalCommittee"]
        elif instance == "intra committee consensus":
            self.txn_block = txn_set
            self.state = ELASTICO_STATES["PBFT Finished"]

    def is_final_member(self):
        """
            tell whether this node is a final committee member or not
        """
        return self.is_final

    def sign(self,data):
        """
            Sign the data i.e. signature
        """
        # make sure that data is string or not
        if type(data) is not str:
            data = str(data)
        digest = SHA256.new()
        digest.update(data.encode())
        signer = PKCS1_v1_5.new(self.key)
        signature = signer.sign(digest)
        return signature

    def verify_sign(self, signature, data, public_key):
        """
            verify whether signature is valid or not 
            if public key is not key object then create a key object
        """
        # print("---verify_sign func---")
        if type(public_key) is str:
            public_key = public_key.encode()
        if type(data) is not str:
            data = str(data)
        if type(public_key) is bytes:
            public_key = RSA.importKey(public_key)
        digest = SHA256.new()
        digest.update(data.encode())
        verifier = PKCS1_v1_5.new(public_key)
        return verifier.verify(digest,signature)

    def broadcast_final_txn(self):
        """
            final committee members will broadcast S(commitmentSet), along with final set of 
            X(txn_block) to everyone in the network
        """
        bool_value , S = consistency_protocol()
        if not bool_value:
            return S
        data = {"commitmentSet" : S, "signature" : self.sign(S) , "identity" : self.identity , "finalTxnBlock" : self.final_block["finalBlock"] , "finalTxnBlock_signature" : self.sign(self.final_block["finalBlock"])}
        print("finalblock-" , self.final_block)
        # final Block sent to ntw
        self.final_block["sent"] = True
        broadcast_to_network(data, "finalTxnBlock")
        if self.state != ELASTICO_STATES["FinalBlockReceived"]:
            self.state = ELASTICO_STATES["FinalBlockSent"]

    def get_committee_members(committee_id):
        """
            Returns all members which have this committee id : committee_list[committee_id]
        """
        pass

    def send_to_final(self):
        """
            Each committee member sends the signed value(txn block after intra committee consensus)
            along with signatures to final committee
        """
        for final_id in self.final_committee_members:
            # here txn_block is a set
            data = {"txnBlock" : self.txn_block , "sign" : self.sign(self.txn_block), "identity" : self.identity}
            message = {"data" : data, "type" : "intraCommitteeBlock" }
            final_id.send(message)
        self.state = ELASTICO_STATES["Intra Consensus Result Sent to Final"]

    def union(data):
        """
            Takes ordered set union of agreed values of committees
        """
        pass

    def validate_signs(signatures):
        """
            validate the signatures, should be at least c/2 + 1 signs
        """
        pass

    def generate_random_strings(self):
        """
            Generate r-bit random strings
        """
        if self.is_f():
            Ri = random_generation(r)
            self.Ri = ("{:0" + str(r) +  "b}").format(Ri)

    def hexdigest(self, message):
        """
            returns the digest for a message
        """
        commitment = SHA256.new()
        commitment.update(message.encode())
        return commitment.hexdigest()

    def get_commitment(self):
        """
            generate commitment for random string Ri. This is done by a
            final committee member
        """
        if self.is_final_member():
            if self.Ri == "":
                self.generate_random_strings()
            commitment = SHA256.new()
            commitment.update(self.Ri.encode())
            return commitment.hexdigest()

    def send_commitment(self):
        """
            send the H(Ri) to the final committe members.This is done by a
            final committee member
        """		
        if self.is_final_member():
            Hash_Ri = self.get_commitment()
            for nodeId in self.committee_members:
                data = {"identity" : self.identity , "Hash_Ri"  : Hash_Ri}
                message = {"data" : data , "type" : "hash"}
                nodeId.send(message)
            self.state = ELASTICO_STATES["CommitmentSentToFinal"]

    def add_commitment(self, final_block):
        """
            ToDo: Check where to use this
            include H(Ri) ie. commitment in final block
        """
        Hash_Ri = self.get_commitment()
        final_block["hash"] = Hash_Ri

    def broadcast_R(self):
        """
            broadcast Ri to all the network
        """
        data = {"Ri" : self.Ri, "identity" : self.identity}
        message = {"data" : data , "type" : "RandomStringBroadcast"}
        self.state = ELASTICO_STATES["BroadcastedR"]
        broadcast_to_network(message, "RandomStringBroadcast")

    def xor_R(self):
        """
            find xor of any random c/2 + 1 r-bit strings to set the epoch randomness
        """
        # ToDo: set_of_Rs must be at least c/2 + 1, so make sure this - done this!
        random_set = SystemRandom().sample(self.set_of_Rs , c//2 + 1)
        xor_val = 0
        for R in random_set:
            xor_val = xor_val ^ int(R, 2)
        self.epoch_randomness = ("{:0" + str(r) +  "b}").format(xor_val)
        return ("{:0" + str(r) +  "b}").format(xor_val) , random_set

    # verify the PoW of the sender
    def verify_PoW(self, identity):
        """
            verify the PoW of the node identity
        """
        # PoW = {"hash" : hash_val, "set_of_Rs" : random_set_R}
        PoW = identity.PoW
        # Valid Hash has D leading '0's (in hex)
        if not PoW["hash"].startswith('0' * D):
            return False
        
        # check Digest for set of Ri strings
        for Ri in PoW["set_of_Rs"]:
            digest = self.hexdigest(Ri)
            if digest not in self.R_commitment_set:
                print("pow failed due to R_commitment_set")
                return False

        # reconstruct epoch randomness

        epoch_randomness = identity.epoch_randomness
        if len(PoW["set_of_Rs"]) > 0:
            xor_val = 0
            for R in PoW["set_of_Rs"]:
                xor_val = xor_val ^ int(R, 2)
            epoch_randomness = ("{:0" + str(r) +  "b}").format(xor_val)
        PK = identity.PK
        IP = identity.IP
        
        # recompute PoW 
        nonce = PoW["nonce"]
            
        digest = SHA256.new()
        digest.update(IP.encode())
        digest.update(PK.encode())
        digest.update(epoch_randomness.encode())
        digest.update(str(nonce).encode())
        hash_val = digest.hexdigest()
        if hash_val.startswith('0' * D) and hash_val == PoW["hash"]:
            # Found a valid Pow, If this doesn't match with PoW["hash"] then Doesn't verify!
            return True
        return False

    def append_to_ledger(self):
        """
        """
        pass

    def execute(self, epoch_txn):
        """
			executing the functions based on the running state
		"""
        # print the current state of node for debug purpose
        # logging.info(self.identity ,  list(ELASTICO_STATES.keys())[ list(ELASTICO_STATES.values()).index(self.state)], "STATE of a committee member")
        print(self.identity ,  list(ELASTICO_STATES.keys())[ list(ELASTICO_STATES.values()).index(self.state)], "STATE of a committee member")

        if self.state == ELASTICO_STATES["NONE"]:
            # compute Pow
            self.compute_PoW()
        elif self.state == ELASTICO_STATES["PoW Computed"]:
            # form identity, when PoW computed
            self.form_identity()
        elif self.state == ELASTICO_STATES["Formed Identity"]:
            # form committee, when formed identity
            self.form_committee()
        elif self.is_directory and self.state == ELASTICO_STATES["RunAsDirectory"]:
            # directory node will receive transactions
            # Receive txns from client for an epoch
            k = 0
            num = len(epoch_txn) // pow(2,s) 
            # loop in sorted order of committee ids
            for identity in range(pow(2,s)):
                if identity == pow(2,s)-1:
                    self.txn[identity] = epoch_txn[ k : ]
                else:
                    self.txn[identity] = epoch_txn[ k : k + num]
                k = k + num
            self.state  = ELASTICO_STATES["RunAsDirectory after-TxnReceived"]
        elif self.state == ELASTICO_STATES["Committee full"]:
            # Now The node should go for Intra committee consensus
            if self.is_directory == False:
                self.run_PBFT(self.txn_block, "intra committee consensus")
            else:
                print("directory member state changed to Committee full(unwanted state)")
                input()	

        elif self.state == ELASTICO_STATES["Formed Committee"]:
            # These Nodes are not part of network
            pass
        elif self.state == ELASTICO_STATES["PBFT Finished"]:
            # send pbft consensus blocks to final committee members
            self.send_to_final()
        
        elif self.is_final_member() and self.state == ELASTICO_STATES["Intra Consensus Result Sent to Final"]:
            # final committee node will collect blocks and merge them
            flag = False
            for commitment_id in range(pow(2,s)):
                if commitment_id not in self.ConsensusMsgCount or self.ConsensusMsgCount[commitment_id] <= c//2:
                    flag = True
                    break
            if flag == False:
                self.verify_and_merge_consensus_data()
            
        elif self.is_final_member() and self.state == ELASTICO_STATES["Merged Consensus Data"]:
            # final committee member runs final pbft
            self.run_PBFT(self.mergedBlock, "final committee consensus")

        elif self.is_final_member() and self.state == ELASTICO_STATES["PBFT Finished-FinalCommittee"]:
            # send the commitment to other final committee members
            self.send_commitment()

        elif self.is_final_member() and self.state == ELASTICO_STATES["CommitmentSentToFinal"]:
            # broadcast final txn block to ntw
            if len(self.commitments) >= c//2 + 1:
                self.BroadcastFinalTxn()

        elif self.state == ELASTICO_STATES["FinalBlockReceived"] and len(self.committee_Members) == c and self.is_directory == False and self.is_final_member():
            # collect final blocks sent by final committee and send to client.
            # Todo : check this send to client
            response = []
            for txnBlock in self.finalBlockbyFinalCommittee:
                if len(self.finalBlockbyFinalCommittee[txnBlock]) >= c//2 + 1:
                    response.append(txnBlock)
                else:
                    print("less block signs : ", len(self.finalBlockbyFinalCommittee[txnBlock]))
            if len(response) > 0:
                self.state = ELASTICO_STATES["FinalBlockSentToClient"]
                return response
        
        elif self.is_final_member() and self.state == ELASTICO_STATES["FinalBlockSentToClient"]:
            # broadcast Ri is done when received commitment has atleast c/2  + 1 signatures
            # ToDo: check this constraint 
            if len(self.new_R_commitment_set) >= c//2 + 1:
                self.broadcast_R()
        
        elif self.state == ELASTICO_STATES["FinalBlockReceived"]:
            pass
                    
        elif self.state == ELASTICO_STATES["ReceivedR"]:
            # Now, the nodes can be reset
            return "reset"

def Run(epoch_txns):
    """
        runs for one epoch
    """
    global network_nodes, ledger, commitment_set
    if len(network_nodes) == 0:
        # E is the list of elastico objects
        for i in range(n):
            logging.info("---Running for processor number--- %s" , i + 1)
            print( "---Running for processor number---" , i + 1)
            network_nodes.append(Elastico())
    epoch_block = set()
    commitment_set = set()

    while True:
        reset_count = 0
        for node in network_nodes:
            # node.lock.acquire()
            # logging.info("executing node")
            response = node.execute(epoch_txns)
            # logging.info("executed node :- %s", node.state)
            # node.lock.release()
            if response == "reset":
                reset_count += 1
                pass
            elif response is not None and len(response) != 0:
                for txn_block in response:
                    print()
                    epoch_block |= eval(txn_block)
        logging.info("reset_count :- %s", reset_count)
        if reset_count == n:
            # ToDo: discuss with sir - earlier I was using broadcast, but it had a problem that anyone can send "reset-all" as message[type]
            for node in network_nodes:
                message = {"type": "reset-all", "data" : node.identity}
                if isinstance(node.identity, Identity):
                    logging.info("send message :- %s", message)
                    node.identity.send(message)
                else:
                    logging.warning("illegal call")
                    print("illegal call")
                    node.reset()
            break

    ledger.append(epoch_block)
    print("ledger block" , ledger)
    input("ledger updated!!")

if __name__ == "__main__":
    logging.basicConfig(filename='./src/server/data/elastico_normally.log',filemode='w',level=logging.DEBUG)
    # epoch_txns - dictionary that maps the epoch number to the list of transactions
    epoch_txns = dict()
    for i in range(5):
        # txns is the list of the transactions in one epoch to which the committees will agree on
        txns = []
        for j in range(3):
            random_num = random_generation(32)
            txns.append(random_num)
        epoch_txns[i] = txns
    for epoch in epoch_txns:
        print("epoch number :-" , epoch + 1 , "started")
        logging.info("epoch number :- %s started", epoch + 1)
        Run(epoch_txns[epoch])
