#June 12, 2022
#use cVDF6.py as basis for this Randomness Beacon

import math
import time
import random
from Crypto.Util import number
from Crypto.Hash import SHA256
from Crypto.Hash import SHA3_384 #for randomness beacon only
from Crypto.Hash import SHA3_512 #for randomness beacon only

#cVDF6.py algorithms for this Randomness Beacon
def Setup(x, bits, t, k):
	
	#Generate checkpoints array
	def genCheckpoints(t,k):
		if t % k == 0:
			x = t // k
			cp = [] #cp for check points
			y = k
			while len(cp) < k + 1: 
				cp.append(x * y)
				y -= 1
		else:
			print('Error: t % k != 0. Exiting Program')
			exit()
		return cp
	cp = genCheckpoints(t,k) #generate cp array
	
	#Generate modulus
	def genMod(bits):

		#Generate prime
		def genPrime(bits):
			potential_prime = 1
			while potential_prime % 4 == 1:
				potential_prime = number.getPrime(bits) #Randomized
			return potential_prime
		
		x = 0
		while x <1: 
			p = genPrime(bits)
			q = genPrime(bits)
			if p != q and q % 4 != 1:
				N = p * q
			x += 1
			s = (p, q) #assign secret here
		return N, s
	N, s = genMod(bits)
		
	#Generate Challenge
	def genChallenge(N,s): #generate random challenge here
		p = s[0]
		q = s[1]
		
		J_p, J_q = 1, 1
	#generate seed x which is a quadratic non-residue of N
		while not  (J_p == 1 and J_q != 1) and not (J_q == 1 and J_p != 1):
			x = random.randrange(2,N)			#Randomized
			J_p = pow(x,(p-1)//2,p)             #Always == 1 or == p-1, use Euler's Criterion
			J_q = pow(x,(q-1)//2,q)             #Always == 1 or == q-1, use Euler's Criterion
		x_0 = pow(x,2,N)
		C = (x, x_0)
		return C
	C = genChallenge(N,s)
	
	#Generate Preimages
	def genPreimage(N, s, C, cp):
		p = s[0]
		q = s[1]
		x_0 = C[1]
		
		omega_p = (p + 1) // 4  #Tonelli Shanks, need p = 3 mod 4, Extend Eulers Criterion for proof
		omega_q = (q + 1) // 4  #Tonelli Shanks, need q = 3 mod 4, Extend Eulers Criterion for proof
	
		beacon_preimages = [] #keep secret
		for i in cp:
			alpha_p = pow(x_0, pow(omega_p,i,p-1), p) #reduce mod p-1 is Eulers Theorem
			alpha_q = pow(x_0, pow(omega_q,i,q-1), q) #reduce mod q-1 is Eulers Theorem
			x_minus_i = ((alpha_p * q * pow(q,-1,p)) + (alpha_q * p * pow(p,-1,q))) % N #Chinese Remainder Theorem to find Mod N. 
			beacon_preimages.append(x_minus_i)
		print('\nSECRET beacon_preimages:', beacon_preimages)
		return beacon_preimages
	beacon_preimages = genPreimage(N, s, C, cp)
	
	#Generate HashTable
	def genHashTable(beacon_preimages):
	#convert beacon_preimages from integers to strings
		beacon_strings = []
		for i in beacon_preimages:
			string = str(i)
			beacon_strings.append(string)
		
	#convert beacon_strings to byte strings
		hash0 = [] #SHA2-256 Hash table
		for i in beacon_strings: 
			byte_string = bytes(i, 'utf-8')
			h = SHA256.new()
			h.update(byte_string)
			hash0.append(h.hexdigest())
		return hash0
	hash0 = genHashTable(beacon_preimages)
	
	state = [beacon_preimages[0]]
	pp = (N, t, k, C, cp, hash0)

	return pp, state 
#return: pp, state,
#pp = [N, t, k, C = (x, x_0), cp, hash0]
#state = [x_minus_t]

#Any party Deterministic Verify
def Verify(pp, state):
	V = 'Reject'
	
	N = pp[0]
	t = pp[1]
	k = pp[2]
	C = pp[3]
	cp = pp[4]
	hash0 = pp[5]

	x = C[0]
	x_0 = C[1]
	
	x_minus_t = state[0]

	def genSHA256(state): 
		string = str(state[-1])
		byte_string = bytes(string, 'utf-8')
		h = SHA256.new()
		h.update(byte_string)
		Hash = h.hexdigest()
		return Hash
	
	if len(state) <= k + 1:
		Hash = genSHA256(state)
		if Hash == hash0[len(state) - 1]:
			#print('\nHash:    ', Hash, 
			#	  '\nhash0[i]:', hash0[len(state) - 1]
			#	 )
			V = 'Accept'
			#print('V0:', V)
			return V

	return V
#return: V = {Accept, Reject}

#Prover Deterministic Eval
def Eval(pp, state):
	N = pp[0]
	t = pp[1]
	k = pp[2]
	C = pp[3]
	cp = pp[4]
	hash0 = pp[5]

	x = C[0]
	x_0 = C[1]
	
	seed = state[-1]
	
	V = Verify(pp, state)

	
	if len(state) < k + 1 and V == 'Accept': #add and verify == accept later
		print('V1:', V, 'continue sequential calculation')
		state_i = pow(seed, pow(2,t//k), N)
		state.append(state_i)
	
	return state
#return state = [x_minus_t, ... x_0]






#RB algorithms, to call cVDF6.py algorithms as needed

def RB_Setup(x, bits, t, k):
	pp, state = Setup(1, bits, t, k)
	return pp, state
#return: pp, state,
#pp = [N, t, k, C = (x, x_0), cp, hash0]
#state = [x_minus_t]

def RB_Tick(pp, state):
	print('\nTick...')
	state = Eval(pp, state)
	print('current state:', state)
	return state
#return: state = [x_{-t}, ... , x_{0}}

def RB_Tock(pp, state):
	print('\nTock...')
	N = pp[0]
	t = pp[1]
	k = pp[2]
	C = pp[3]
	cp = pp[4]
	hash0 = pp[5]
	
	def genSHA2_256(state): 
		string = str(state[-2])
		byte_string = bytes(string, 'utf-8')
		h = SHA256.new()
		h.update(byte_string)
		Hash = h.hexdigest()
		return Hash

	
	def genSHA3_512(state): 
		string = str(state[-2])
		byte_string = bytes(string, 'utf-8')
		h = SHA3_512.new()
		h.update(byte_string)
		Hash = h.hexdigest()
		return Hash


	pulse = genSHA3_512(state)
	sha256 = genSHA2_256(state)
	print(
		'pulse:', pulse,
		'\nsha256:', sha256
		)
	return pulse



def RB_Verify(pp, state):
	V = Verify(pp, state)
	return V

#Now run functions
bits = 32
t = 1500
k = 5

#Algo.1 TTP Randomised Setup
start_time = time.time()
pp, state = RB_Setup(1, bits, t, k)
print('pp = [N, checkpoints, C = (x, x_0)]', pp,
	'\nstate:', state,
	 )
print('ALGO-RB_Set:' , round(time.time() - start_time , 4), 'seconds')

while len(state) <= k:
	#Algo.2 RB Deterministic Tick
	start_time = time.time()
	state = RB_Tick(pp, state)
	print('ALGO-RB_Tick:' , round(time.time() - start_time , 4), 'seconds')

	#Algo.3 RB Deterministic Tock
	start_time = time.time()
	pulse = RB_Tock(pp, state)
	print('ALGO-RB_Tock:' , round(time.time() - start_time , 4), 'seconds')

start_time = time.time()
V = RB_Verify(pp, state)
print('\nV:', V)
print('ALGO-RB_Verify:' , round(time.time() - start_time , 4), 'seconds')