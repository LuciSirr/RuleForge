#!/usr/bin/env python3

#author: Lucia Sirova (xsirov01)
import argparse
import sys
import os

from symspellpy import SymSpell, Verbosity
from symspellpy.editdistance import EditDistance, DistanceAlgorithm

import numpy as np


class MatrixGenerator:
    def __init__(self):
        self.distance_matrix = []
        self.directory = None  # Input directory
        self.passwords = []  # Passwords from wordlist files
        self.edit_distance_calculator = EditDistance(DistanceAlgorithm.LEVENSHTEIN_FAST)
        self.max_password_length = 20

    def process_args(self):
        parser = argparse.ArgumentParser(prog='MatrixGenerator')
        parser.add_argument('--generate_from', required=True, help='Directory containing wordlist files')

        #Define maximal lenght of password
        parser.add_argument('--max_password_length', type=int, default=20,help='Define the maximum length of a password (default: 20)')
        
        args = parser.parse_args()
        self.directory = args.generate_from
        self.max_password_length = args.max_password_length

    def process_passwords(self, wordlist):
        unique_passwords = set() #use set for storing only unique passwords
        try:
            with open(wordlist,'r', encoding='ascii', errors='surrogateescape') as file:
                for line in file:   
                    for word in line.split():
                        if (word.isascii() and len(word) < self.max_password_length): #append only passwords that are not longer than 30 characters
                            unique_passwords.add(word)
            #store unique passwords in array self.passwords
            for password in unique_passwords:
                self.passwords.append(password)
        except:
            print("Error opening file", file=sys.stderr)
            exit(1)

    def levenstein_distance_symspell(self, wordlist):
        print("Starting calculation...")
        total_passwords = len(self.passwords)
        # Initialize the distance matrix with zeros
        self.distance_matrix = np.zeros((total_passwords, total_passwords))
        for i, password_col in enumerate(self.passwords):
            for j in range(i, len(self.passwords)):
                if i == j:
                    self.distance_matrix[i][j] = 0
                else:
                    distance = self.edit_distance_calculator.compare(password_col, self.passwords[j], max_distance=100)
                    self.distance_matrix[i][j] = distance
                    self.distance_matrix[j][i] = distance
            print(f"Progress: {i+1}/{total_passwords}", end='\r')
        print("\nCalculation complete.")
        np.save(os.path.splitext(wordlist)[0] + '_distance_matrix.npy', self.distance_matrix)
        print(self.distance_matrix)

    def process_directory(self):
        for filename in os.listdir(self.directory):
            if filename.endswith('.txt'):  
                filepath = os.path.join(self.directory, filename)
                if os.path.isfile(filepath):
                    print(f"Processing {filename}...")
                    self.passwords = [] 
                    self.process_passwords(filepath)
                    self.levenstein_distance_symspell(filepath)



if __name__ == "__main__":
    matrix_generator = MatrixGenerator()
    matrix_generator.process_args()
    matrix_generator.process_directory()
