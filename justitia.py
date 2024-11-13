#!/usr/bin/env python
encoding='utf-8'
#
#    Copyright 2024 Erkam Uzun
#
#    This file is part of justitia.
#
#    justitia is free software: you can redistribute it and/or modify
#    it under the terms of the GNU General Public License as published by
#    the Free Software Foundation, either version 3 of the License, or
#    (at your option) any later version.
#
#    justitia is distributed in the hope that it will be useful,
#    but WITHOUT ANY WARRANTY; without even the implied warranty of
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#    GNU General Public License for more details.
#
#    You should have received a copy of the GNU General Public License
#    along with justitia.  If not, see <http://www.gnu.org/licenses/>.
#
#   Note: The fuzzy extractor functions are modified from Carter Yageman's fuzzy_extractor ('https://github.com/carter-yagemann/python-fuzzy-extractor') to 
#   avoid generating low-entropy keys from the source biometric.

"""A Python implementation of Justitia"""

__author__ = 'Erkam Uzun'
__email__ = 'euzun@gatech.edu'
__copyright__ = 'Copyright (c) 2024 Erkam Uzun'
__license__ = 'GPLv3+'
__version__ = '0.1'
__url__ = 'https://github.com/euzun/justitia.git'
__download_url__ = 'https://github.com/euzun/justitia.git'
__description__ = 'A Python implementation of Justitia (Uzun et al. "Cryptographic key derivation from biometric inferences for remote authentication")'

from math import log
from os import urandom
from fastpbkdf2 import pbkdf2_hmac
import numpy as np
from sklearn.preprocessing import normalize
import pickle
import argparse
import sys
from itertools import accumulate
from scipy import stats
from scipy.stats import mode

def generateLSH(emb_arr, lsh_bit_len, *hyperplanes):
    '''
    Locality Sensitive Hash (LSH) generator.
    :param emb_len: The length of embedding (feature) array.
    :param lsh_len: The length in bits of LSH.
    :param hyperplanes: Optional paramater for hyperplanes to generate LSH with same hyperplane used before. 
        This could be saved on enrollment and passed on query.
    '''
    emb_len=np.shape(emb_arr)[1]
    l=2
    n=lsh_bit_len//l
    if not hyperplanes:
        v=normalize(np.random.normal(0, 1.0,(lsh_bit_len,emb_len)),norm='l2', axis=1)
        w=np.zeros(np.shape(v))
        for i in range(l):
            for j in range(1,n+1):
                w[i*n+j-1,:]=v[i*n+j-1,:]
                for k in range(1,j):
                    w[i*n+j-1,:]=np.subtract(w[i*n+j-1,:],np.multiply( np.multiply(w[i*n+k-1], v[i*n+j-1]) ,w[i*n+k-1]) )
                w[i*n+j-1,:]=normalize(w[i*n+j-1,:].reshape(1, -1),norm='l2')
        hyperplanes=w.T
    else:
        hyperplanes=hyperplanes[0]
    
    # Calculate LSH values for all emb_vectors
    lsh_arr=1*(np.dot(emb_arr,hyperplanes) >= 0)

    return lsh_arr, hyperplanes
    
# Following functions are for Fuzzy Extractor generate and reproduce methods.
def feGenerate(value, bit_mask, sub_length, ham_err):
    """Takes a source value and produces 
    - a random secret (this could be passed as a parameter)
    - public helpers to reproduce the secret.


    This method should be used once at enrollment.

    Note that the "public helper" is actually a tuple. This whole tuple should be
    passed as the helpers argument to feReproduce().

    :param value: the value to generate cryptographic keys for.
    :param bit_mask: a mask to guide choosing a helper's subsampling bit from.
    :param sub_length: The length in bits of how many 1s will be kept in subsamples. 
    :param ham_err: Hamming error. The number of bits that can be flipped in the
        source value and still produce the same key with probability (1 - rep_err).
    :rtype: (secret, helper)
    """
    hash_func='sha256'
    sec_len=4 # security parameter length
    rep_err=0.001 # Reproduce error. The probability that a source value within ham_err will not produce the same key (default: 0.001).
    nonce_len=16
    length=len(value)
    cipher_len = length + sec_len

    # Calculate the number of helper values needed to be able to reproduce
    # secret given ham_err and rep_err. See "Reusable Fuzzy Extractors for
    # Low-Entropy Distributions" by Canetti, et al. for details.
    bits = length * 8
    const = float(ham_err) / log(bits)
    num_helpers = (bits ** const) * log(float(2) / rep_err, 2)

    # num_helpers needs to be an integer
    num_helpers = int(round(num_helpers))

    if isinstance(value, (bytes, str)):
        value = np.frombuffer(value, dtype=np.uint8)

    secret = np.frombuffer(urandom(length), dtype=np.uint8)
    secret_pad = np.concatenate((secret, np.zeros(sec_len, dtype=np.uint8)))

    nonces = np.zeros((num_helpers, nonce_len), dtype=np.uint8)
    masks = np.zeros((num_helpers, length), dtype=np.uint8)
    digests = np.zeros((num_helpers, cipher_len), dtype=np.uint8)
    
    # secure some bits by burning them. to prevent (in the worst case) revealing full biometric information.
    umask_ind=np.where(bit_mask==1)[0]
    burn_mask_i=np.random.choice(umask_ind,20,replace=False)
    bit_mask[burn_mask_i]=0

    umask_ind=np.where(bit_mask==1)[0]
    for helper in range(num_helpers):
        bit_mask_h=bit_mask.copy()
        nrof_zerod_bits=max(int(np.sum(bit_mask)-sub_length),0)
        if nrof_zerod_bits>0:
            sub_mask_i=np.random.choice(umask_ind,nrof_zerod_bits,replace=False)
            bit_mask_h[sub_mask_i]=0
        nonces[helper] = np.frombuffer(urandom(nonce_len), dtype=np.uint8)
        masks[helper] = np.packbits(bit_mask_h,-1)
    
    # By masking the value with random masks, we adjust the probability that given
    # another noisy reading of the same source, enough bits will match for 
    # the "new reading & mask" to equal the "old reading & mask".
    vectors = np.bitwise_and(masks, value)

    # The "digital locker" is a simple cyrpto primitive made by hashing a "secret" xor a "value".
    # The only efficient way to get the value back is to know the secret, which can then be hashed again xor the ciphertext.
    # This is referred to as locking and unlocking the digital locker, respectively.
    for helper in range(num_helpers):
        d_vector = vectors[helper].tobytes()
        d_nonce = nonces[helper].tobytes()
        digest = pbkdf2_hmac(hash_func, d_vector, d_nonce, 1, cipher_len)
        digests[helper] = np.frombuffer(digest, dtype=np.uint8)

    ciphers = np.bitwise_xor(digests, secret_pad)

    return (secret.tobytes(), (ciphers, masks, nonces))

def feReproduce(value, helpers):
    """Takes a source value and a public helper and produces a key

    Given a helper value that matches and a source value that is close to
    those produced by generate, the same secret will be produced.

    :param value: the value to reproduce a secret for.
    :param helpers: the previously generated public helper.
    :rtype: secret or None
    """
    hash_func='sha256'
    length=len(value)
    sec_len=4 # security parameter length
    cipher_len = length + sec_len

    if isinstance(value, (bytes, str)):
        value = np.frombuffer(value, dtype=np.uint8)

    if length != len(value):
        raise ValueError('Cannot reproduce key for value of different length')

    ciphers = helpers[0]
    masks = helpers[1]
    nonces = helpers[2]
    num_helpers = np.shape(ciphers)[0]

    vectors = np.bitwise_and(masks, value)

    digests = np.zeros((num_helpers, cipher_len), dtype=np.uint8)
    for helper in range(num_helpers):
        d_vector = vectors[helper].tobytes()
        d_nonce = nonces[helper].tobytes()
        digest = pbkdf2_hmac(hash_func, d_vector, d_nonce, 1, cipher_len)
        digests[helper] = np.frombuffer(digest, dtype=np.uint8)

    plains = np.bitwise_xor(digests, ciphers)

    # When the secret was stored in the digital lockers, extra null bytes were added
    # onto the end, which makes it each to detect if we've successfully unlocked the locker.

    checks = np.sum(plains[:, -sec_len:], axis=1)
    for check in range(num_helpers):
        if checks[check] == 0:
            return plains[check, :-sec_len].tobytes()

    return None

def parse_arguments(argv):
    parser = argparse.ArgumentParser()

    parser.add_argument('EMB_DIR', type=str,
        help='Path to the embeddings directory containing [emb_arr,labels,paths]')
    parser.add_argument('ENR_ID', type=int,
        help='Index of enrollment person (embedding label) id [0-49]', default=0)
    parser.add_argument('QUE_ID', type=int,
        help='Index of query person (embedding label) id [0-49]', default=0)
    parser.add_argument('LSH_BIT_LEN', type=int,
        help='Length of LSH in bits [64,128,192,256..]', default=128)
    parser.add_argument('MASK_PROB', type=float,
        help='Parameter for noise cancellation masking probability [0,0.1,0.2,0.4,0.6,0.8,0.9]', default=0.9)
    parser.add_argument('NROF_SUB_BITS', type=int,
        help='Number of bits subsampled on FE. default=64', default=64)
    parser.add_argument('FE_ERR_THR', type=int,
        help='Number of error bits that fuzzy extractor can tolerate. e.g., 2,4,6,8,10,12',default=2)
    
    return parser.parse_args(argv)

def pickSampleEmbeddings(emb_arr,lab_arr, enr_id, que_id):
    # get unique labels and "c_labels" that give how many samples from each label.
    _,c_labels=np.unique(lab_arr,return_counts=True)
    c_labels = np.array(list(accumulate(c_labels)))
    if enr_id==0:
        start=0
    else:
        start=c_labels[enr_id-1]
    end=c_labels[enr_id]
    
    enr_emb_arrays=emb_arr[start:end]
    # if enrollment and query IDs are same, split samples to half/half
    if enr_id==que_id:
        nrof_samples=np.shape(enr_emb_arrays)[0]
        que_emb_arrays=enr_emb_arrays[int(nrof_samples/2):]
        enr_emb_arrays=enr_emb_arrays[0:int(nrof_samples/2)]
    else:
        if que_id==0:
            start=0
        else:
            start=c_labels[que_id-1]
        end=c_labels[que_id]
        que_emb_arrays=emb_arr[start:end]
    
    return enr_emb_arrays, que_emb_arrays

# Calculate the robust bits that are same with "mask_pr" probability over all sample biometrics (lsh vectors).
def getRobustBitMask(lsh_arr,mask_pr):
    if mask_pr>0:
        nrof_samples=np.shape(lsh_arr)[0]
        lsh_mode_bit_counts=mode(lsh_arr,axis=0).count
        msk=1*(nrof_samples*mask_pr<=lsh_mode_bit_counts)
        return msk
    else:
        return np.array([1]*np.shape(lsh_arr)[1],dtype=int)

def getRobustLSH(lsh_arr, msk):
    lsh_arr=np.multiply(lsh_arr, msk)
    robust_lsh=mode(lsh_arr,axis=0).mode
    return robust_lsh

def enroll(enr_emb_arrays):
    # Generate Locality Sensitive Hashes (LSH) in "lsh_bit_len" bits of each embeddings of enrollment and query samples.
    enr_lsh_arrays,hyperplanes=generateLSH(enr_emb_arrays,lsh_bit_len)
    enr_msk=getRobustBitMask(enr_lsh_arrays,mask_prob)
    enr_lsh_bits=getRobustLSH(enr_lsh_arrays,enr_msk)
    enr_lsh_bytes=np.packbits(enr_lsh_bits,-1)# pack bits into byte array to give fuzzy extractor
    secret, helpers=feGenerate(enr_lsh_bytes,enr_msk,nrof_sub_bits,fe_err_thr)
    return secret,helpers,hyperplanes

def query(que_emb_arrays,helpers,hyperplanes):
    que_lsh_arrays,_=generateLSH(que_emb_arrays,lsh_bit_len,hyperplanes)
    que_msk=getRobustBitMask(que_lsh_arrays,mask_prob)
    que_lsh_bits=getRobustLSH(que_lsh_arrays,que_msk)
    que_lsh_bytes=np.packbits(que_lsh_bits,-1)
    recoveredSecret=feReproduce(que_lsh_bytes,helpers)
    return recoveredSecret

if __name__ == '__main__':
    args=parse_arguments(sys.argv[1:])

    emb_dir=args.EMB_DIR
    enr_id=args.ENR_ID
    que_id=args.QUE_ID
    lsh_bit_len=args.LSH_BIT_LEN
    mask_prob=args.MASK_PROB
    nrof_sub_bits=args.NROF_SUB_BITS
    fe_err_thr=args.FE_ERR_THR
   
   # lfw_clean_embeddings.p has embeddings of 50 people. 
   # loading different embeddings are up to you. 
    with open(emb_dir, "rb") as file:
        mat = pickle.load(file, encoding="latin1")
    emb_arr=mat[0]
    lab_arr=mat[1]
    
    # I will test same and different peoples enrollment/query embeddings as a successful and failed recovery.
    # you can play with the labels of enrollment and query embeddings.
    enr_emb_arrays, que_emb_arrays=pickSampleEmbeddings(emb_arr,lab_arr,enr_id,que_id)
    
    # In enrollment, "secret" is locked user "enr_id"'s embeddings.
    secret,helpers,hyperplanes=enroll(enr_emb_arrays)
    # In query, "recoveredSecret" is unlocked user "que_id"'s embeddings.
    recoveredSecret=query(que_emb_arrays,helpers,hyperplanes)
    
    # Expected outcome:
    # If enr_id== que_id, then "secret" must be equal to "recoveredSecret".
    # Otherwise, "recoveredSecret" value should be None.
    if secret==recoveredSecret:
        output= "True Positive" if enr_id==que_id else "False Positive"
        result="%s. secret: [%s] is locked with enrollment_id:%d. recoveredSecret: [%s] is recovered with query_id: %d"%(output,secret.hex(),enr_id,recoveredSecret.hex(),que_id)
    else:
        output= "False Negative" if enr_id==que_id else "True Negative"
        result="%s. secret: [%s] is locked with enrollment_id:%d. recoveredSecret: [%s] is recovered with query_id: %d"%(output,secret.hex(),enr_id,recoveredSecret,que_id)
    print(result)