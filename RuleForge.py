# #!/usr/bin/env python3

#author: Lucia Sirova (xsirov01)
import argparse
import sys
import os
import json

from symspellpy.editdistance import EditDistance, DistanceAlgorithm


import numpy as np


from sklearn.cluster import DBSCAN
from sklearn.cluster import AgglomerativeClustering
from sklearn.cluster import AffinityPropagation


import Levenshtein as lev


from collections import Counter


class RuleGenerator:
    def __init__(self):
        self.wordlist = None #input wordlist file
        self.rule_file = None #output rule file

        #clustering options
        self.DBSCAN = False
        self.HAC = False
        self.AP = False

        self.passwords = []
        self.distance_matrix = [] #distance matrix with various edit distances of passwords
        self.clusters = {} 
        self.cluster_representatives = {}
        self.chunk_size = 100000
        self.chunks = [] #chunks of passwords, used for chunking large input file
        self.chunk_index = 0 

        self.rules = [] #generated rules
        self.rules_priority = {}

        self.edit_distance_calculator = EditDistance(DistanceAlgorithm.LEVENSHTEIN_FAST) #init distance matrix calculator

        #functions representing each rule
        #lambda functions sourced from PACK/rulegen.py: https://github.com/iphelix/pack/blob/master/rulegen.py
        #author: Peter Kacherginsky (iphelix)
        self.rule_lambda_functions = {
            ":": lambda x: x,
            "l": lambda x: x.lower(),
            "u": lambda x: x.upper(),
            "c": lambda x: x.capitalize(),
            "tN": lambda x: x.swapcase(),
            "TN": lambda x, y: x[:y] + x[y].swapcase() + x[y+1:],
            "t": lambda x: x.swapcase(),     
            "zN": lambda x, y: x[0]*y+x,                      
            "ZN": lambda x, y: x+x[-1]*y,
            "sXY": lambda x, y, z: x.replace(y,z),
            "$X": lambda x, y: x + y,
            "^X": lambda x, y: y + x,
            "[" : lambda x: x[1:],
            "]" : lambda x: x[:-1],
            "DN": lambda x,y: x[:y]+x[y+1:],
            "iNX": lambda x,y,z: x[:y]+z+x[y:],
            "oNX": lambda x,y,z: x[:y]+z+x[y+1:],
            "r": lambda x: x[::-1],
            "{" : lambda x: x[1:]+x[0],
            "}" : lambda x: x[-1]+x[:-1],
        }
    

    #parse input arguments
    def process_args(self):
            parser = argparse.ArgumentParser(prog='RuleForge')
            parser.add_argument('--wordlist', nargs=1, help='Specify path to input wordlist.')
            parser.add_argument('--rulefile', nargs=1, required=True, help='Specify name of output .rule file.')

            #When true take precomputed matrix
            parser.add_argument('--distance_matrix_precomputed', action='store_true', help='Allows to use precomputed distance matrix.')

            #Create rulefile with top n rules
            parser.add_argument('--most_frequent', nargs=1, help='Specify number of rules to be saved in output .rule file.')

            #Flags for clustering methods
            #DBSCAN 
            parser.add_argument('--dbscan', action='store_true', help='Cluster with DBSCAN.') #cluster with DBSCAN
            parser.add_argument('--min_points', type=int, default=3, help='The maximum distance between two samples for one to be considered as in the neighborhood of the other. Integer value.') #the number of samples in a neighborhood for a point to be considered as a core point - int
            parser.add_argument('--eps', type=int, default=2, help=' The number of samples in a neighborhood for a point to be considered as a core point. Integer value.') #the maximum distance between two samples for one to be considered as in the neighborhood of the other - int
            
            #HAC
            parser.add_argument('--hac', action='store_true', help='Cluster with HAC.') #cluster with HAC
            parser.add_argument('--distance_threshold', type=int, default=4,  help='The linkage distance threshold at or above which clusters will not be merged. Integer value.') #the linkage distance threshold at or above which clusters will not be merged - int

            #Affinity propagation
            parser.add_argument('--ap', action='store_true', help='Cluster with AP.') #cluster with AP
            parser.add_argument('--convergence_iter', type=int, default=50, help='Damping factor between 0.5 and 1. Float value.') #number of iterations to wait for convergence - int
            parser.add_argument('--damping', type=float, default=0.9, help='Number of iterations to wait for convergence. Integer value between 1 and ~200.') #damping factor between 0.5 and 1 - float

            
            #Use custom rule priority
            parser.add_argument('--rule_priority', nargs=1, help='Specify path to file with rule priority.')

            #Define maximal lenght of password
            parser.add_argument('--max_password_length', type=int, default=20,help='Define the maximum length of a password (default: 20).')

            #Define size of chunk
            parser.add_argument('--chunk_size', type=int, default=100000,help='Define the chunk size for parsing the input (default: 10000).')

            #Enables clustering with external
            parser.add_argument('--stdin',action='store_true', help='Use when clustering with external DBSCAN and MDBSCAN.')

            parser.add_argument('--remove_outlier',action='store_true', help='Wont generate rules from outlier clusters.') #do not use outliers for rule generation
            parser.add_argument('--verbose',action='store_true', help='Prints out information about rule generating process.') #verbose mode


            args = parser.parse_args()

            #load wordlist if clustering with base clustering methods
            if args.wordlist:
                self.wordlist = args.wordlist[0]
            elif not args.stdin:
                print('You must select a wordfile.',file=sys.stderr)
                exit(1)
            self.rule_file = args.rulefile[0]

            self.most_frequent = int(args.most_frequent[0]) if args.most_frequent else None

            self.rule_priority_file = args.rule_priority[0] if args.rule_priority else None

            self.DBSCAN = args.dbscan
            self.min_points = args.min_points if self.DBSCAN else None 
            self.eps = args.eps if self.DBSCAN else None  

            self.HAC = args.hac
            self.distance_threshold = args.distance_threshold if self.HAC else None

            self.AP = args.ap
            self.convergence_iter = args.convergence_iter if self.AP else None
            self.dampning = args.damping if self.AP else None

            self.dm_precomputed = args.distance_matrix_precomputed

            self.max_password_length = args.max_password_length

            self.chunk_size = args.chunk_size

            self.STDIN = args.stdin

            self.remove_outlier = args.remove_outlier
            
            self.verbose = args.verbose

            if not (self.DBSCAN or self.HAC or self.AP or self.STDIN):
                print("No clustering method specified", file=sys.stderr)
                exit(1)


    #load passwords from input wordlist 
    def process_passwords(self):
        if self.STDIN:
            self.external_clustering()
            return


        unique_passwords = set() #use set for storing only unique passwords
        try:    
            with open(self.wordlist,'r', encoding='utf-8', errors='surrogateescape') as file:
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

        self.get_distance_matrix()

    
    #load rule priority from file, if file not present set default
    def create_priority_dict_with_functions(self):
        try:
            with open(self.rule_priority_file, 'r') as file:
                rules = file.readlines()    
        except:
            # set default rules
            rules = [
                "l",
                "u",
                "c",
                "t",
                "TN",
                "zN",
                "ZN",
                "$X",
                "^X",
                "[",
                "]",
                "DN",
                "iNX",
                "oNX",
                "}",
                "{",
                "r",
                "sXY",
            ]
 
            
        priority = 1
        for rule in rules:
            rule_name = rule.strip() 
            if rule_name in self.rule_lambda_functions:
                self.rules_priority[rule_name] = {'priority': priority, 'func': self.rule_lambda_functions[rule_name]}
                priority += 1
            else:
                print(f"Warning: No lambda function defined for rule '{rule_name}'")       


    #compute or load distance matrix
    def get_distance_matrix(self):
        if (self.dm_precomputed):
            #loading precomputed distance matrix
            filename_without_extension, _ = os.path.splitext(self.wordlist)
            try:
                self.distance_matrix = np.load(filename_without_extension+'_distance_matrix.npy')
            except:
                print("Unable to load distance matrix", file=sys.stderr)
                exit(1)
            number_of_chunks = self.chunking()
            if (number_of_chunks > 1):
                print("Chunking with precomputed distance matrix is not possible, please select bigger chunk size or cluster with external clustering (DBSCAN, MDBSCAN)", file=sys.stderr)
                exit(1)
            self.select_clustering() #after successfully loading distance matrix, cluster passwords
        else:
            number_of_chunks = self.chunking() #compute number of chunks
            self.chunks_edit_distance(number_of_chunks) #compute edit distance for each chunk of passwords



                
    #compute number of chunks and create chunks for passwords for clustering
    def chunking(self):
        number_of_chunks = len(self.passwords) / self.chunk_size
        #separating passwords into chunks
        for x in range(0, len(self.passwords), self.chunk_size):
            chunk = self.passwords[x:x + self.chunk_size]
            self.chunks.append(chunk)
        return number_of_chunks

    #compute edit distance for each chunk
    def chunks_edit_distance(self, number_of_chunks):
        while self.chunk_index < number_of_chunks:
            self.levenstein_distance_symspell()
            self.chunk_index += 1

    #computing edit distance matrix
    def levenstein_distance_symspell(self):
        total_passwords = len(self.chunks[self.chunk_index])
        if (self.verbose):
         print("Starting calculation...")
        
        #initialize the distance matrix with zeros
        self.distance_matrix = np.zeros((total_passwords, total_passwords))
        for i, password_col in enumerate(self.chunks[self.chunk_index]):
            for j in range(i, len(self.chunks[self.chunk_index])): 
                #comparing same passwords, therefore distance is always 0 
                if i == j:
                    self.distance_matrix[i][j] = 0
                else:
                    distance = self.edit_distance_calculator.compare(password_col, self.chunks[self.chunk_index][j], max_distance=self.max_password_length) #computation of edit distance between 2 passwords
                    #since the matrix is symmetrical, the values are mirrored
                    self.distance_matrix[i][j] = distance
                    self.distance_matrix[j][i] = distance
            if (self.verbose):
                print(f"Progress: {i+1}/{total_passwords}", end='\r') #display the progess of computation
        self.select_clustering()

    #choose clustering method
    def select_clustering(self):
        if (self.DBSCAN):
            self.DBSCAN_clustering()
        elif (self.HAC):
            self.HAC_clustering()
        elif (self.AP):
            self.AP_clustering()
        #choosing clustering with external clustering methods - DBSCAN or MDBSCAN
        elif (self.STDIN):
            self.external_clustering()
             

    #clustering with various methods
    def DBSCAN_clustering(self):
        self.model = DBSCAN(eps=self.eps,min_samples=self.min_points, metric="precomputed")
        self.clusters = self.process_model_data()
        self.compute_cluster_representative()
        self.get_rules_from_cluster()


    def HAC_clustering(self):
        self.model = AgglomerativeClustering(n_clusters=None, metric='precomputed',linkage='single', distance_threshold=self.distance_threshold)
        self.clusters = self.process_model_data()
        self.compute_cluster_representative()
        self.get_rules_from_cluster()

    def AP_clustering(self):            
        self.distance_matrix = -1 * self.distance_matrix.astype(np.float64)
        self.model = AffinityPropagation(affinity="precomputed", damping=self.dampning, convergence_iter=self.convergence_iter)
        self.clusters = self.process_model_data()
        self.get_cluster_representative_AP()
        self.get_rules_from_cluster()

    #DBSCAN (SymSpell version) and MDBSCAN
    def external_clustering(self):
        self.clusters = json.load(sys.stdin)
        self.compute_cluster_representative_external()
        self.get_rules_from_cluster()

    #computes clusters based on model model, creates dictionary according to cluster label
    def process_model_data(self):
        cluster_labels = self.model.fit_predict(self.distance_matrix)
        clusters = {}
        for index, label in enumerate(cluster_labels):
            if label not in clusters:
                clusters[label] = [self.chunks[self.chunk_index][index]]
            else:
                clusters[label].append(self.chunks[self.chunk_index][index])
        return clusters       
    
    #computation of cluster representative
    def compute_cluster_representative(self):
        for label, passwords_in_cluster in self.clusters.items():
            cluster_indices = []
            
            #get indices of passwords in passwords array
            for password in passwords_in_cluster:
                index = self.chunks[self.chunk_index].index(password)
                cluster_indices.append(index)
            
            #get part of distance matrix according to indices 
            cluster_distance_matrix = self.distance_matrix[cluster_indices, :][:, cluster_indices]
            
            #calculate edit distance mean of passwords in cluster
            edit_distance_mean = np.mean(cluster_distance_matrix, axis=0)
            closest_index = np.argmin(edit_distance_mean)
            self.cluster_representatives[label] = passwords_in_cluster[closest_index]


    #get a same format of cluster representative with ap
    def get_cluster_representative_AP(self):
        for label in np.unique(self.model.labels_):
            exemplar = self.passwords[self.model.cluster_centers_indices_[label]]
            self.cluster_representatives[label] = exemplar


    #computation of cluster representative
    def compute_cluster_representative_external(self):
        for (label,cluster) in self.clusters.items():
            if self.remove_outlier and label == '-1':
                continue
            
            for password in cluster:
                distances = []
                for other_password in cluster:
                    distances.append(self.edit_distance_calculator.compare(password,other_password,max_distance=100))
                edit_distance_mean = np.mean(distances, axis=0)
            representative = np.argmin(edit_distance_mean)    
            self.cluster_representatives[label] = cluster[representative]

    #get rules from each cluster, optionally dont generate rules from outlier clusters
    def get_rules_from_cluster(self):
        for label, passwords_in_cluster in self.clusters.items():
            if self.remove_outlier and label == '-1' and self.STDIN:
                continue
             
            representative = self.cluster_representatives[label] #get representative of given cluster
            if self.verbose:
                print(f"Cluster {label} (Representative: {representative}): {', '.join(passwords_in_cluster)}")
            cluster_rules = [] 

            #generate rules from one password from cluster
            for password in passwords_in_cluster:
                word_rules = self.generate_hashcat_rules(representative, password) #rules from one password
                if (self.verbose):
                    print(f"rules to convert {representative} to {password}")
                    print(word_rules)
                #add newly generated rules to rules that belong to this one cluster
                cluster_rules.extend(rule for rule in word_rules if rule not in cluster_rules)
                cluster_rules.extend(word_rules)
                
            #add newly generated rules from cluster to final ruleset
            self.rules.extend(cluster_rules)
            
        #save rules to .rule output file
        if (self.most_frequent == None):
            self.most_frequent = len(self.rules)
 
        self.save_frequent_rules_to_file()

    #save rules to .rule output ruleset, final ruleset is sorted according to rule frequency, optionally top n rules are selected
    def save_frequent_rules_to_file(self):
        counter = Counter()
        for rule in self.rules:
            counter[rule] += 1

        with open(self.rule_file , 'w', encoding='utf-8', errors='surrogateescape') as file:
            for rule, count in counter.most_common(self.most_frequent):
                file.write(f"{rule}\n")


    #convert int to hashcat format
    #int_to_hashcat() function sourced from PACK/rulegen.py: https://github.com/iphelix/pack/blob/master/rulegen.py
    #author: Peter Kacherginsky (iphelix)
    def int_to_hashcat(self,N):
        if N < 10:
            return str(N)
        else:
            return chr(65 + N - 10)
    

    #detecting a length of sequence of same letters on the beginning of password
    def count_duplicate_first(self,password):
        count = 0
        for i in range(1, len(password)):
            if password[i] == password[0]:
                count += 1
            else:
                break
        return count
    
    #detecting a length of sequence of same letters on the beginning of password
    def count_duplicate_last(self,password):
        count = 0
        for i in range(len(password) - 2, -1, -1):
            if password[i] == password[(len(password) - 1)]:
                count += 1
            else:
                break
        return count

    #searching for applicable rule
    def find_applicable_rule(self, current, target):
        edit_operations_base = len(lev.editops(current, target)) #number of operations needed to transform representative
        edit_operations = lev.editops(current, target) #operations needed to transform representative
        new_pass = current
        for rule, details in sorted(self.rules_priority.items(), key=lambda x: x[1]['priority']):
            func = details['func'] #lamdba function with current priority
            arg_count = func.__code__.co_argcount #number of args this lambda function requires

            #0 agrs
            if (arg_count == 1):
                new_pass = details['func'](current)

            #1 arg
            elif (arg_count == 2):
                if (rule == "DN" or rule == "TN"):
                        if (edit_operations[0][1] < len(current) and edit_operations[0][2] < len(target)):
                            new_pass = details['func'](current, edit_operations[0][1])
                            rule = rule.replace("N",self.int_to_hashcat(edit_operations[0][1]))
                            rule = rule.replace("X",target[edit_operations[0][1]])
                elif (rule == "zN"):
                    if (edit_operations[0][1] < len(current) and edit_operations[0][2] < len(target)):
                        count_first = self.count_duplicate_first(target)
                        if (count_first > 1):
                            new_pass = details['func'](current, count_first)
                            rule = rule.replace("N",self.int_to_hashcat(count_first))
                            rule = rule.replace("X",target[edit_operations[0][1]])
                elif (rule == "ZN"):
                    if (edit_operations[0][1] < len(current) and edit_operations[0][2] < len(target)):
                        count_last = self.count_duplicate_last(target)
                        if (count_last > 1):
                            new_pass = details['func'](current, count_last)
                            rule = rule.replace("N", self.int_to_hashcat(count_last))
                            rule = rule.replace("X",target[edit_operations[0][1]])
                elif (rule == "^X"):
                    positions=[]
                    #getting prepend mangling rules in correct order, not reversed
                    for op in edit_operations:
                        if (op[1] == 0):
                            positions.append(op)
                
                    if (len(positions) != 0):
                        last_operation = positions[-1] 
                        new_pass = details['func'](current, target[last_operation[2]])
                        rule = rule.replace("X",target[last_operation[2]])
                        
                else: 
                    if (edit_operations[0][2] == len(target)):
                        new_pass = details['func'](current, target[edit_operations[0][2]-1])
                        rule = rule.replace("N",self.int_to_hashcat(edit_operations[0][1]))
                        rule = rule.replace("X",target[edit_operations[0][2]-1])

                    else:
                        new_pass = details['func'](current, target[edit_operations[0][2]])
                        rule = rule.replace("N",self.int_to_hashcat(edit_operations[0][1]))
                        rule = rule.replace("X",target[edit_operations[0][1]])
            
            #2 args
            elif (arg_count == 3):
                if (edit_operations[0][1] < len(current) and edit_operations[0][2] < len(target)):
                    if (rule == "iNX" or rule == "oNX"):
                        new_pass = details['func'](current, edit_operations[0][1], target[edit_operations[0][2]])
                        rule = rule.replace("X",target[edit_operations[0][1]])
                        rule = rule.replace("Y",target[edit_operations[0][2]])
                    else:
                        new_pass = details['func'](current, current[edit_operations[0][1]], target[edit_operations[0][2]])
                        rule = rule.replace("X",current[edit_operations[0][1]])
                        rule = rule.replace("Y",target[edit_operations[0][2]])
                rule = rule.replace("N",self.int_to_hashcat(edit_operations[0][1]))
            
            edit_operations_new = len(lev.editops(new_pass, target))
            if edit_operations_new < edit_operations_base:
                return rule, new_pass #if number of transformation operations is lowered, applicable rule was found
            else:
                new_pass = current #if number of transformation operations wasnt lowered, revert password back to previous version and look for another rule
            
    #get rules from password and representant        
    def generate_hashcat_rules(self, representant, password):
        generated_rules = []
        current_password = representant
        if (current_password == password):
            generated_rules.append(":")

        #look for single rules until password is not changed to representant
        while (current_password != password):
            result = self.find_applicable_rule(current_password, password)
            if result is not None:
                rule, new_password = result
                if rule:
                    generated_rules.append(rule)
                    current_password = new_password
            else:
                print(f"No applicable rule found to transform {current_password} closer to {password}.")
                break
        

        single_rule = ' '.join(generated_rules)
        generated_rules.append(single_rule)

        return generated_rules
        
            

if __name__ == "__main__":
    ruleGenerator = RuleGenerator()
    ruleGenerator.process_args()
    ruleGenerator.create_priority_dict_with_functions()
    ruleGenerator.process_passwords()
