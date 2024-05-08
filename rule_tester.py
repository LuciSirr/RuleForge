#!/usr/bin/env python3

#Author: Lucia Sirova (xsirov01)

import os
import subprocess
import sys
import re
import csv
import argparse
from collections import Counter
import time

class Test_rules:
    def __init__(self):
        self.parameters_file = None
        self.all_hac_parameters=[]
        self.all_dbscan_parameters=[]
        self.all_ap_parameters=[]
        self.all_mdbscan_parameters=[]

        self.best_hit_rates = {
            "dbscan" : 0,
            "hac" : 0,
            "ap" : 0,
            "drdak" : 0,
            "pack" : 0
        }

        self.stats_dbscan = {
            "hit_rates": [],
            "rule_count": [],
            "best_hit_rate": [],
            "cracked": [],
            "min_pts" : "",
            "eps:": ""
        }

        self.stats_ap = {
            "hit_rates": [],
            "rule_count": [],
            "best_hit_rate": [],
            "cracked": [],
            "convergence_iter" : "",
            "damping": ""
        }

        self.stats_hac = {
            "hit_rates": [],
            "rule_count": [],
            "best_hit_rate": [],
            "cracked": [],
            "distance_threshold": []

        }

        self.stats_mdbscan= {
            "hit_rates": [],
            "rule_count": [],
            "best_hit_rate": [],
            "cracked": [],
            "eps1": "",
            "eps2": "",
            "min_pts": ""

        }        

        self.stats_drdak = {
            "hit_rates": [],
            "rule_count": [],
            "best_hit_rate": [],
            "cracked": []
        }

        self.stats_pack = {
            "hit_rates": [],
            "rule_count": [],
            "best_hit_rate": [],
            "cracked": []
        }

        
    #parse input arguments
    def parse_args(self):
        parser = argparse.ArgumentParser(description="Process the directories and parameters for clustering.")

        parser.add_argument('--directory_rules', type=str, required=True, help='Directory for rules')
        parser.add_argument('--directory_wordlists', type=str, required=True, help='Directory for wordlist')
        parser.add_argument('--directory_passwords', type=str, required=True, help='Directory for password cracking')
        parser.add_argument('--clustering_parameters', type=str, required=True, help='Parameters for clustering')

        parser.add_argument('--test_dbscan', action='store_true', help='Flag to enable only DBSCAN testing', required=False)
        parser.add_argument('--test_ap', action='store_true', help='Flag to enable only Affinity propagation testing', required=False)
        parser.add_argument('--test_hac', action='store_true', help='Flag to enable only HAC testing', required=False)
        parser.add_argument('--test_mdbscan', action='store_true', help='Flag to enable only MDBSCAN testing', required=False)

        parser.add_argument('--distance_matrix_precomputed', action='store_true', help='Distance matrices for rule generating are precomputed', required=False)
        parser.add_argument('--test_frequent', type=int, required=False, help='Optional: Test hit rate of x most frequent rules', default=None)

        args = parser.parse_args()

        #Validate whether directories exist
        for directory in [args.directory_rules, args.directory_wordlists, args.directory_passwords]:
            if not os.path.isdir(directory):
                print(f"Directory {directory} not found.")
                sys.exit(1)

        self.directory_rules = args.directory_rules
        self.directory_wordlists = args.directory_wordlists
        self.directory_passwords = args.directory_passwords
        self.parameters_file = args.clustering_parameters
        self.number_of_frequent_rules = args.test_frequent if args.test_frequent else None

        self.test_dbscan = args.test_dbscan
        self.test_hac = args.test_hac
        self.test_ap = args.test_ap
        self.test_mdbscan = args.test_mdbscan

        self.dm_precomuted = args.distance_matrix_precomputed

        if (self.test_dbscan == False and self.test_hac == False and self.test_ap == False and self.test_mdbscan == False):
            self.test_all = True
        else:
            self.test_all = False

        self.parse_clustering_parameters()
        

            
    #Parse clusting parameters from input file
    def parse_clustering_parameters(self):
        with open(self.parameters_file, 'r') as file:
            for line in file:
                parts = line.strip().split(',')
                if (parts[0] == "hac"):
                    self.all_hac_parameters.append(parts[1])
                elif (parts[0] == "dbscan"):
                    self.all_dbscan_parameters.append({'min_pts': parts[1], 'eps': parts[2]})
                elif (parts[0] == "ap"):
                    self.all_ap_parameters.append({'damping': parts[1], 'convergence_iter': parts[2]})
                elif (parts[0] == "mdbscan"):
                    self.all_mdbscan_parameters.append({'eps1': parts[1], 'eps2' : parts[2], 'min_pts': parts[3]})


    #Extracts line with information about number of recovered passwords from hashcat output
    def extract_recovered_line(self,hashcat_output):
        hashcat_lines = hashcat_output.splitlines()
        recovered_line = None
        for line in hashcat_lines:
            if line.startswith("Recovered"):
                recovered_line = line
                percentage_pattern = r"\d+/\d+ \(\d+\.\d+%\)"
                match = re.search(percentage_pattern, recovered_line)
                if match:
                    recovered_line = match.group()
                break
        return recovered_line

    #Separates number of cracked passwords, number of total passwords and percentage from recovered line from hashcat output
    def parse_recovered_line(self,recovered_line):
        try:
            # Extract the "X/Y (Z%)" part
            match = re.search(r"(\d+)/(\d+) \((\d+\.\d+)%\)", recovered_line)
            if match:
                cracked = int(match.group(1))
                total = int(match.group(2))
                percentage = float(match.group(3))
                return cracked, total, percentage
            else:
                print("No match found in the line: ", recovered_line)
                return 0, 0, 0.0
        except Exception as e:
            print(f"Error parsing recovered line '{recovered_line}': {e}")
            return 0, 0, 0.0


    #Counts number of rules in rulefile
    def count_rules(self,rule_file):
        count = 0
        with open(rule_file, 'r') as file:
            for line in file:
                if not(line.isspace()):
                    count +=1
        return count

    #Clears arrays with statistics
    def clear_stats(self, stats):
        stats['hit_rates'] = []
        stats['rule_count'] = []
        stats['best_hit_rate'] = []
        stats['cracked'] = []

        return stats
    
    #Creates .csv file with statistics for each rule generation tool
    def write_statistics_to_csv(self,method_name, stats,number_of_tests, total_passwords, parameter_index):
        filename = f"{method_name}_statistics.csv"
        mode = 'w' #write mode is used when initializing the .csv file
        if (parameter_index != 0):
            mode = 'a' #append mode is used when adding new entries to .csv file
        with open(filename, mode=mode, newline='') as file:
            writer = csv.writer(file)
            csv_header = ['Method',
                        'Number of tests', 
                        'Average hit rate', 
                        'Average number of rules', 
                        'Number of passwords cracked x/y']
            
            
            average_hit_rate = sum(stats['hit_rates']) / len(stats['hit_rates']) if stats['hit_rates'] else 0
            average_rules = sum(stats['rule_count'])  / len(stats['rule_count']) if stats['rule_count'] else 0
            total_cracked = sum(stats['cracked'])
            cracked_text = f"{total_cracked}/{total_passwords}"

            csv_row =  [method_name, 
                number_of_tests, 
                f"{average_hit_rate:.2f}%", 
                f"{average_rules:.2f}",
                cracked_text]

            if (method_name == "dbscan"):
                csv_header.append("min_pts")
                csv_header.append("eps")

                csv_row.append(stats['min_pts'])
                csv_row.append(stats['eps'])

            if (method_name == "ap"):
                csv_header.append("damping")
                csv_header.append("convergence_iter")

                csv_row.append(stats['damping'])
                csv_row.append(stats['convergence_iter'])

            if (method_name == "hac"):
                csv_header.append("distance_threshold")
                csv_row.append(stats['distance_threshold'])

            if (method_name == "mdbscan"):
                csv_header.append("min_pts")
                csv_header.append("eps1")
                csv_header.append("eps2")

                csv_row.append(stats['min_pts'])
                csv_row.append(stats['eps1'])
                csv_row.append(stats['eps2'])
    
            #if .csv file is newly initialized write header
            if mode == 'w': 
                writer.writerow(csv_header)
          
            writer.writerow(csv_row)
    
        print(f"Statistics written to {filename}")

    #gets x most frequent rules from ruleset generated by rulegen/pack tool
    def get_frequent_rules_from_pack(self):
        most_frequent_rules = 'analysis.rule'
        with open("analysis-sorted.rule", 'r') as source_file, open(most_frequent_rules, 'w') as destination_file:
    
            for i in range(self.number_of_frequent_rules):
                line = source_file.readline()
                
                destination_file.write(line)

    #gets x most frequent rules from ruleset generated by rule_generator/drdak tool
    #rule_generator script has been modified to generate duplicate rules intentionally, allowing for sorting based on rule frequency
    def get_frequent_rules_from_drdak(self,rule_file_path):
        counter = Counter()
        with open(rule_file_path, 'r', encoding='ascii', errors='surrogateescape') as file:
            for line in file:
                rule = line.strip()
                counter[rule] += 1
        with open(rule_file_path, 'w', encoding='ascii', errors='surrogateescape') as file:
            for rule, count in counter.most_common(self.number_of_frequent_rules):
                file.write(f"{rule}\n")   


    #constructs command for rule generating process
    def construct_ruleForge_command(self, wordlist, rulefile, clustering_method, params):
        base_command =  ["python3.9",
                         "RuleForge.py",
                         "--wordlist","<wordlist>", 
                         "--rulefile",
                         "<rulefile_name>_<clustering_method>.rule",
                         "--<clustering_method>","--rule_priority",
                         "rules_priority.txt"]
        
        
        #replace placeholders
        for i, part in enumerate(base_command):
            base_command[i] = part.replace('<wordlist>', wordlist)\
                                  .replace('<rulefile_name>', rulefile)\
                                  .replace('<clustering_method>', clustering_method)\
                                  
        for key, value in params.items():
            base_command.extend([f"--{key}", str(value)])

        if (self.number_of_frequent_rules != None):
            base_command.extend([f"--most_frequent", str(self.number_of_frequent_rules)])

        if (self.dm_precomuted):
            base_command.extend([f"--distance_matrix_precomputed"])

        return base_command
    

    #executing rule generating commands
    def execute_rule_generating_command(self, command):
        start_time = time.time()
        subprocess.run(command, stdout=subprocess.PIPE)
        end_time = time.time()
        return end_time - start_time
    
    #updates stats variable for each rule generation tool
    def update_stats(self, recovered_line, stats, rule_count,params):
        recovered, _, recovered_percentage = self.parse_recovered_line(recovered_line)
        
        stats['hit_rates'].append(recovered_percentage)
        stats['rule_count'].append(rule_count)
        stats['cracked'].append(recovered)

        #mdbscan and dbscan stats
        if 'eps' in params:
            stats['eps'] = str(params['eps'])
        if 'eps1' in params:
            stats['eps1'] = str(params['eps1'])
        if 'eps2' in params:
            stats['eps2'] = str(params['eps2'])
        if 'min_pts' in params:
            stats['min_pts'] = str(params['min_pts'])

        #hac stats    
        if 'distance_threshold' in params:
            stats['distance_threshold'] = str(params['distance_threshold'])

        #ap stats   
        if 'damping' in params:
            stats['damping'] = str(params['damping'])
        if 'convergence_iter' in params:
            stats['convergence_iter'] = str(params['convergence_iter'])

       
    #generates rules and runs hashcat to test rule efficiency
    def test_rules(self):
        number_of_tests= 0 #counts number of cracking sessions with hashcat
        number_of_passwords_total = 0 #counts total number of passwords attemted to crack
        csv_file_path = "password_cracking_statistics.csv" 
        with open(csv_file_path, mode='w', newline='') as file:
            writer = csv.writer(file)
            header = ["Method", "Rules", "Dictionary", "Target", "Recovered Rate (%)", "Number of Rules","Rule generation time", "Rule generating rate" ,"Parameters"]
            writer.writerow(header)
            parameter_index = 0
            
    
            while (len(self.all_mdbscan_parameters) > parameter_index or len(self.all_ap_parameters) > parameter_index or len(self.all_dbscan_parameters) > parameter_index or len(self.all_hac_parameters) > parameter_index):                  
                # Create rule sets from given wordlists
                for rule_file in os.listdir(self.directory_rules):
                    if rule_file.endswith(".txt"):
                        filename_no_ext = os.path.splitext(rule_file)[0]

                        #construct dbscan command
                        if (parameter_index < len(self.all_dbscan_parameters)):
                            dbscan_command = self.construct_ruleForge_command(os.path.join(self.directory_rules, rule_file), filename_no_ext, "dbscan", {'min_points': self.all_dbscan_parameters[parameter_index]['min_pts'], 'eps': self.all_dbscan_parameters[parameter_index]['eps']})

                        #construct hac command
                        if(parameter_index < len(self.all_hac_parameters)):
                            hac_command = self.construct_ruleForge_command(os.path.join(self.directory_rules, rule_file), filename_no_ext, "hac", {'distance_threshold': self.all_hac_parameters[parameter_index]})

                        #construct ap command
                        if (parameter_index < len(self.all_ap_parameters)):
                            ap_command = self.construct_ruleForge_command(os.path.join(self.directory_rules, rule_file), filename_no_ext, "ap", {'damping': self.all_ap_parameters[parameter_index]['damping'], 'convergence_iter': self.all_ap_parameters[parameter_index]['convergence_iter']})


                        #construct mdbscan command
                        if (parameter_index < len(self.all_mdbscan_parameters)):
                            mdbscan_command = [ "./MDBSCAN/MDBSCAN/bin/Release/net7.0/MDBSCAN",
                                                    self.all_mdbscan_parameters[parameter_index]['eps1'],
                                                    self.all_mdbscan_parameters[parameter_index]['eps2'],
                                                    self.all_mdbscan_parameters[parameter_index]['min_pts'],
                                                    "<rulefile>",
                                                    "|",
                                                    "python3.9",
                                                    "RuleForge.py",
                                                    "--rulefile", 
                                                    "<rulefile_name>_mdbscan.rule",
                                                    "--stdin", "--rule_priority", 
                                                    "rules_priority.txt", 
                                                ]
                        
                        
                        if (self.test_all):
                            print("Generating rules -Dominik Drdak/rule_generator")
                            execution_time_drdak = self.execute_rule_generating_command(["python3.9", "rule_generator.py", "-f", os.path.join(self.directory_rules, rule_file), "--damping", "0.9", "--convergence_iter", "50"])
                            #get most frequent rules from Dominik Drdak rule_generator ruleset
                            if (self.number_of_frequent_rules != None):
                                self.get_frequent_rules_from_drdak(os.path.join(self.directory_rules, filename_no_ext) + ".out")


                            print("Generating rules -PACK")
                            execution_time_pack = self.execute_rule_generating_command(["python3.9", "rulegen.py", os.path.join(self.directory_rules, rule_file), "-q"])
                            #get most frequent rules from Dominik Drdak rule_generator ruleset
                            if (self.number_of_frequent_rules != None):
                                self.get_frequent_rules_from_pack()

                        if (self.test_mdbscan or self.test_all):
                            print("Generating rules -MDBSCAN")
                            mdbscan_command[4] = str(os.path.join(self.directory_rules, rule_file))
                            mdbscan_command[9] = mdbscan_command[9].replace("<rulefile_name>", filename_no_ext)
   
                            if (self.number_of_frequent_rules != None):
                                mdbscan_command.append("--most_frequent")
                                mdbscan_command.append(str(self.number_of_frequent_rules))
                            
                            start_time = time.time()
                            subprocess.run(' '.join(mdbscan_command), shell=True)
                            end_time = time.time()
                            execution_time_mdbscan = end_time - start_time
                            

          
                        if (self.test_dbscan or self.test_all):
                            print("Generating rules -DBSCAN")
                            execution_time_dbscan = self.execute_rule_generating_command(dbscan_command)

                        if (self.test_hac or self.test_all):
                            print("Generating rules -HAC")
                            execution_time_hac = self.execute_rule_generating_command(hac_command)

                        if (self.test_ap or self.test_all):
                            print("Generating rules -AP")
                            execution_time_ap = self.execute_rule_generating_command(ap_command)

                        #Get attack wordlists for rule based attack
                        for dictionary_for_attack in os.listdir(self.directory_wordlists):
                            #Get target wordlists for rule based attack
                            for target_dictionary in os.listdir(self.directory_passwords):
                                if (target_dictionary == dictionary_for_attack): 
                                    continue
                        
                                print("###############################")         
                                print("Cracking: ",target_dictionary)
                                print("Dictionary: ", dictionary_for_attack)
                                print("Rules generated from: ",rule_file)
                                
                                if (self.test_all):
                                    #run attack with randomly generated hashcat rules
                                    number_of_random_rules = 100
                                    if (self.number_of_frequent_rules != None):
                                        number_of_random_rules = self.number_of_frequent_rules
                                    print("RANDOM:")
                                    result = subprocess.run(["hashcat", "-a", "0", "-m", "99999", os.path.join(self.directory_passwords, target_dictionary), os.path.join(self.directory_wordlists, dictionary_for_attack), "--generate-rules="+str(number_of_random_rules),"--potfile-disable"], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
                                    recovered_line = self.extract_recovered_line(result.stdout)
                                    print("Recovered: ",recovered_line)
                           
                                    
                                    print("Number of rules: ", number_of_random_rules)
                                    random_cracked, _, random_recovered = self.parse_recovered_line(recovered_line)
                                    writer.writerow(['random',
                                                    'random generated', 
                                                    dictionary_for_attack, 
                                                    target_dictionary, 
                                                    f"{random_recovered:.2f}%",
                                                    str(number_of_random_rules),
                                                    '-',
                                                    '-',                                
                                                    ])


                                    #run hashcat with rules from rule_generator/Dominik Drdak
                                    print("rule_generator/Dominik Drdak:")
                                    result = subprocess.run(["hashcat", "-a", "0", "-m", "99999", os.path.join(self.directory_passwords, target_dictionary), os.path.join(self.directory_wordlists, dictionary_for_attack), "-r", os.path.join(self.directory_rules, filename_no_ext) + ".out", "--potfile-disable"], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
                                    recovered_line = self.extract_recovered_line(result.stdout)
                                    print("Recovered: ",recovered_line)
                                    print("Number of rules: ",self.count_rules(os.path.join(self.directory_rules, filename_no_ext) + ".out"))
                                    _, _, drdak_recovered = self.parse_recovered_line(recovered_line)
                                    #saving rule_generator stats
                                    self.update_stats(recovered_line, self.stats_drdak, self.count_rules(os.path.join(self.directory_rules, filename_no_ext) + ".out"), {} )

                                    #saving attack results to password_cracking_statistics.csv
                                    writer.writerow(['drdak', 
                                                    rule_file, 
                                                    dictionary_for_attack, 
                                                    target_dictionary, 
                                                    f"{drdak_recovered:.2f}%",
                                                    self.count_rules(os.path.join(self.directory_rules, filename_no_ext) + ".out"),
                                                    execution_time_drdak,
                                                    execution_time_drdak/ self.count_rules(os.path.join(self.directory_rules, filename_no_ext) + ".out"),
                                                    ])
                                

                                    #run hashcat with rules from PACK
                                    print("PACK: ")
                                    result = subprocess.run(["hashcat", "-a", "0", "-m", "99999", os.path.join(self.directory_passwords, target_dictionary), os.path.join(self.directory_wordlists, dictionary_for_attack), "-r", "analysis.rule", "--potfile-disable"], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
                                    recovered_line = self.extract_recovered_line(result.stdout)
                                    print("Recovered: ",recovered_line)
                                    print("Number of rules: ",self.count_rules("analysis.rule"))
                                    _, _, pack_recovered = self.parse_recovered_line(recovered_line)
                                    #saving PACK stats
                                    self.update_stats(recovered_line, self.stats_pack, self.count_rules("analysis.rule"), {} )
                                  
                                   #saving attack results to password_cracking_statistics.csv
                                    writer.writerow(['pack',
                                                    rule_file, 
                                                    dictionary_for_attack, 
                                                    target_dictionary, 
                                                    f"{pack_recovered:.2f}%",
                                                    self.count_rules("analysis.rule"),
                                                    execution_time_pack,
                                                    execution_time_pack/self.count_rules("analysis.rule"),
                                                    ])
                                    
                                #run hashcat with rules from RuleForge MDBSCAN    
                                if (self.test_mdbscan or self.test_all):
                                    print("MDBSCAN: ")
                                    result = subprocess.run(["hashcat", "-a", "0", "-m", "99999", os.path.join(self.directory_passwords, target_dictionary), os.path.join(self.directory_wordlists, dictionary_for_attack), "-r", filename_no_ext + "_mdbscan.rule", "--potfile-disable"], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
                                    recovered_line = self.extract_recovered_line(result.stdout)
                                    print("Recovered: ",recovered_line)
                                    print("Number of rules: ",self.count_rules(filename_no_ext + "_mdbscan.rule"))
                                    _, _, mdbscan_recovered = self.parse_recovered_line(recovered_line)
                                    #saving mdbscan stats
                                    self.update_stats(recovered_line, self.stats_mdbscan, self.count_rules(filename_no_ext + "_mdbscan.rule"), 
                                                      {'eps1': str(self.all_mdbscan_parameters[parameter_index]['eps1']), 
                                                       'eps2' : str(self.all_mdbscan_parameters[parameter_index]['eps2']),
                                                       'min_pts': str(self.all_mdbscan_parameters[parameter_index]['min_pts'])})

                                    #saving attack results to password_cracking_statistics.csv
                                    writer.writerow(['mdbscan',
                                                    rule_file,
                                                    dictionary_for_attack,
                                                    target_dictionary, 
                                                    f"{mdbscan_recovered:.2f}%",
                                                    self.count_rules(filename_no_ext + "_mdbscan.rule"),
                                                    execution_time_mdbscan,
                                                    execution_time_mdbscan/self.count_rules(filename_no_ext + "_mdbscan.rule"),
                                                    "--eps1: " + str(self.all_mdbscan_parameters[parameter_index]['eps1']),
                                                    "--eps2: " + str(self.all_mdbscan_parameters[parameter_index]['eps2']),
                                                    "--min_pts: " + str(self.all_mdbscan_parameters[parameter_index]['min_pts'])
                                                    ])        
                                    
                                #run hashcat with rules from RuleForge DBSCAN    
                                if (self.test_dbscan or self.test_all):
                                    print("DBSCAN:")
                                    result = subprocess.run(["hashcat", "-a", "0", "-m", "99999", os.path.join(self.directory_passwords, target_dictionary), os.path.join(self.directory_wordlists, dictionary_for_attack), "-r", filename_no_ext + "_dbscan.rule","--potfile-disable"], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
                                    recovered_line = self.extract_recovered_line(result.stdout)
                                    print("Recovered: ",recovered_line)
                                    print("Number of rules: ",self.count_rules(filename_no_ext + "_dbscan.rule"))
                                    _, _, dbscan_recovered = self.parse_recovered_line(recovered_line)
                                    #saving dbscan stats
                                    self.update_stats(recovered_line, self.stats_dbscan, self.count_rules(filename_no_ext + "_dbscan.rule"), 
                                                      {'eps': str(self.all_dbscan_parameters[parameter_index]['eps']),
                                                       'min_pts': str(self.all_dbscan_parameters[parameter_index]['min_pts'])})

                                    #saving attack results to password_cracking_statistics.csv
                                    writer.writerow(['dbscan',
                                                    rule_file, 
                                                    dictionary_for_attack, 
                                                    target_dictionary, 
                                                    f"{dbscan_recovered:.2f}%",
                                                    self.count_rules(filename_no_ext + "_dbscan.rule"),
                                                    execution_time_dbscan,
                                                    execution_time_dbscan/self.count_rules(filename_no_ext + "_dbscan.rule"),
                                                    "min points: " + str(self.all_dbscan_parameters[parameter_index]['min_pts']), 
                                                    "eps: " + str(self.all_dbscan_parameters[parameter_index]['eps'])])

                                #run hashcat with rules from RuleForge HAC
                                if (self.test_hac or self.test_all):
                                    print("HAC:")
                                    result = subprocess.run(["hashcat", "-a", "0", "-m", "99999", os.path.join(self.directory_passwords, target_dictionary), os.path.join(self.directory_wordlists, dictionary_for_attack), "-r", filename_no_ext + "_hac.rule", "--potfile-disable"], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
                                    recovered_line = self.extract_recovered_line(result.stdout)
                                    print("Recovered: ",recovered_line)
                                    print("Number of rules: ",self.count_rules(filename_no_ext + "_hac.rule"))
                                    _, _, hac_recovered = self.parse_recovered_line(recovered_line)
                                    #saving hac stats
                                    self.update_stats(recovered_line, self.stats_hac, self.count_rules(filename_no_ext + "_hac.rule"), 
                                                    {'distance_threshold': str(self.all_hac_parameters[parameter_index])})

                                 
                                    #saving attack results to password_cracking_statistics.csv
                                    writer.writerow(['hac', 
                                                    rule_file, 
                                                    dictionary_for_attack, 
                                                    target_dictionary, 
                                                    f"{hac_recovered:.2f}%", 
                                                    self.count_rules(filename_no_ext + "_hac.rule"),
                                                    execution_time_hac,
                                                    execution_time_hac/self.count_rules(filename_no_ext + "_hac.rule"),
                                                    "distance_threshold: " + str(self.all_hac_parameters[parameter_index])
                                                    ])

                                #run hashcat with rules from RuleForge AP
                                if (self.test_ap or self.test_all):
                                    print("AP: ")
                                    result = subprocess.run(["hashcat", "-a", "0", "-m", "99999", os.path.join(self.directory_passwords, target_dictionary), os.path.join(self.directory_wordlists, dictionary_for_attack), "-r", filename_no_ext + "_ap.rule", "--potfile-disable"], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
                                    recovered_line = self.extract_recovered_line(result.stdout)
                                    print("Recovered: ",recovered_line)
                                    print("Number of rules: ",self.count_rules(filename_no_ext + "_ap.rule"))
                                    _, _, ap_recovered = self.parse_recovered_line(recovered_line)
                                    #saving ap stats
                                    self.update_stats(recovered_line, self.stats_ap, self.count_rules(filename_no_ext + "_ap.rule"), 
                                                      {'damping': str(self.all_ap_parameters[parameter_index]['damping']),
                                                       'convergence_iter': str(self.all_ap_parameters[parameter_index]['convergence_iter'])})

                                    #saving attack results to password_cracking_statistics.csv
                                    writer.writerow(['ap',
                                                    rule_file,
                                                    dictionary_for_attack,
                                                    target_dictionary, 
                                                    f"{ap_recovered:.2f}%",
                                                    self.count_rules(filename_no_ext + "_ap.rule"),
                                                    execution_time_ap,
                                                    execution_time_ap/self.count_rules(filename_no_ext + "_ap.rule"),
                                                    "--convergence_iter: " + str(self.all_ap_parameters[parameter_index]['convergence_iter']),
                                                    "--damping: " + str(self.all_ap_parameters[parameter_index]['damping'])
                                                    ])

                                
                                _, number_of_passwords, _ = self.parse_recovered_line(recovered_line)
                                number_of_passwords_total += number_of_passwords
                                number_of_tests += 1
                

                #writing statistics to .csv files for each tool/method
                if (self.test_dbscan or self.test_all):
                    self.write_statistics_to_csv("dbscan", self.stats_dbscan, number_of_tests, number_of_passwords_total,parameter_index)
                if (self.test_hac or self.test_all):
                    self.write_statistics_to_csv("hac", self.stats_hac,  number_of_tests, number_of_passwords_total, parameter_index)
                if (self.test_ap or self.test_all):
                    self.write_statistics_to_csv("ap", self.stats_ap,  number_of_tests, number_of_passwords_total, parameter_index)
                if (self.test_mdbscan or self.test_all):
                    self.write_statistics_to_csv("mdbscan", self.stats_mdbscan, number_of_tests, number_of_passwords_total, parameter_index)
                if (parameter_index == 0 and self.test_all):
                    self.write_statistics_to_csv("drdak", self.stats_drdak,  number_of_tests, number_of_passwords_total, parameter_index)
                    self.write_statistics_to_csv("pack", self.stats_pack, number_of_tests, number_of_passwords_total, parameter_index)  
                   
                #clearing stats arrays for entries with new clustering parameters
                self.stats_mdbscan = self.clear_stats(self.stats_mdbscan)
                self.stats_dbscan = self.clear_stats(self.stats_dbscan)
                self.stats_hac = self.clear_stats(self.stats_hac)
                self.stats_ap = self.clear_stats(self.stats_ap)
                self.stats_mdbscan = self.clear_stats(self.stats_mdbscan)
                parameter_index += 1  
                number_of_tests=0
             
            

if __name__ == "__main__":
    test_rules = Test_rules()
    test_rules.parse_args()
    test_rules.test_rules()
   
