
# RuleForge 
Lucia Šírová Bachelor's thesis: Automated creation of password mangling rules using machine learning methods
## Description

This repository contains RuleForge, a ML-Based Password-Mangling Rule Generator for Dictionary Attacks. 



## Requirements

Before you begin, ensure you have met the following requirements:

  

**Python:** This project requires Python 3.9 or newer.

**pip:** This project uses pip3 for managing Python packages.

  

**.NET SDK 7.0** Required for compiling and running (M)DSBCAN clustering.
#### RuleForge Installation with pip3:

````
pip3 install -r requirements.txt
````

#### Compiling MDBSCAN

````
cd MDBSCAN
dotnet build -c Release
````




## Usage:
### RuleForge
Running base version of RuleForge (clustering with AP, HAC and DBSCAN):
````
python3.9 RuleForge.py --wordlist <wordlist_file> --rulefile <rule_file> ( --hac | --ap | --dbscan)
````
##### Required Arguments:

`--wordlist <wordlist_file>`: Path to the wordlist file. This is the input wordlist for rule generation.

`--rulefile <rule_file>`: Path to the output file where the generated rules will be saved.


##### Optional Arguments:
`--verbose`:Prints out information about rule generating process.

`--rule_priority <rule_priority_file>`: Path to the priority rule file, for seleting rules to be used and prioritizing rule types.

`--most_frequent <number_of_rules>`: Output .rule file will contain specified number of most frequent rules.

`--max_password_length <password_length>`: Define the maximum length of a password (default: 20).

`--chunk_size <chunk_size>`: Define the chunk size for parsing the input (default: 10000).

`--stdin`: Enables clustering with external clustering method (MDBSCAN and DBSCAN).

`--remove_outlier`: Wont generate rules from outlier clusters.

`--distance_matrix_precomputed`: Allows to use precomputed distance matrix. 


##### Clustering Algorithms Options:

`--dbscan`: Use DBSCAN clustering algorithm.

- -`--eps <value>`: The maximum distance between two samples for one to be considered as in the neighborhood of the other. Integer value.

- -`--min_pts <value>`: The number of samples in a neighborhood for a point to be considered as a core point. Integer value.

`--hac`: Use hierarchical agglomerative clustering algorithm.

-  `--distance_threshold <value>`: The linkage distance threshold at or above which clusters will not be merged. Integer value.

 `--ap`: Use affinity propagation clustering algorithm.

-  `--damping <value>`: Damping factor between 0.5 and 1. Float value.

-  `--convergence_iter <value>`: Number of iterations to wait for convergence. Integer value between 1 and ~200.
---
### RuleForge - Expanded (M)DBSCAN
Running RuleForge with external (M)DBSCAN clustering, provided by Bc. Viktor Rucky,
For clustering with DBSCAN:

````

./MDBSCAN/MDBSCAN/bin/Release/net7.0/MDBSCAN <eps> <min_pts> <wordlist_file> | python3.9 RuleForge.py --rulefile <rule_file> --stdin

````

For clustering with MDBSCAN:

````

./MDBSCAN/MDBSCAN/bin/Release/net7.0/MDBSCAN <eps1> <eps2> <min_pts> <wordlist_file> | python3.9 RuleForge.py --rulefile <rule_file> --stdin

````

---
### rule_tester

Testing hit rates of various rule generators (RuleForge, rule_generator/Dominik Drdak, rulegen/PACK).

#### Requirements
- Hashcat
- rule_priority.txt file containing rule priority 
- rulegen.py (PACK) and rule_generator.py (Dominik Drdak script) - these scripts are not mandatory if running rule_tester just for RuleForge


````
python3.9 rule_tester.py --directory_rules <rules_dictionaries> --directory_wordlists <wordlist_dictionaries> `--directory_passwords <passwords> --clustering_parameters <clustering_parameters>
````


##### Required Arguments:

  `--directory_rules <rules_dictionaries>`: Path to folder containing dictionaries for rule generation.

  `--directory_wordlists <wordlist_dictionaries>`: Path to folder with attack wordlists to be used for rule-based attacks.

  `--directory_passwords <passwords>`: Path to folder with passwords to be cracked.

  `--clustering_parameters <clustering_parameters>`: Path to file with parameters for clustering analysis.

  

##### Optional Arguments:
 `--test_dbscan`: Enable this flag to perform testing only with DBSCAN clustering.
 
 `--test_ap`: Enable this flag to perform testing only with Affinity Propagation clustering.
 
 `--test_hac`: Enable this flag to perform testing only with Hierarchical Agglomerative Clustering.
 
 `--test_mdbscan`:  Enable this flag to perform testing only with MDBSCAN clustering.
 
 `--test_frequent <number_of_rules>`: Test hit rate of the x most frequent rules. If not specified, tests will be performed with whole ruleset.

#### clustering parameters .txt file argument format
````
(method,damping,convergence iter)
ap,0.5,100
(method,min pts,eps)
dbcan,2,4
(method,distance threshold)
hac,3
(method, eps1, eps2, min_pts)
mdbscan,2,0.25,3
````

#### clustering parameters .txt file example
````
ap,0.5,50
ap,0.5,100
dbscan,2,2
dbscan,4,2
hac,2
hac,3
mdbscan,2,0.25,3
mdbscan,3,0.25,3
````
#### rule_priority.txt file format example
````
l
u
c
t
TN
[
]
$X
^X
zN
ZN
DN
iNX
oNX
}
{
r
sXY
````
---
### distance_matrix_generator
Allows to generate .npy distance matrices for rule generation

``
python3.9 distance_matrix_generator.py --generate_from <folder_with_wordlists>
``

When generating distance matrices, ensure that the `--max_password_length` is set to the same value as used during RuleForge rule generation.
##### Required Arguments:

 `--generate_from <folder_with_wordlists>`: Path to folder containing dictionaries from which the distance matrix will be generated.
##### Optional Arguments:
`--max_password_length <password_length>`: Define the maximum length of a password (default: 20).