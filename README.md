# yarrp-toolkit

Tool to analyse a number of output files from yarrp.

## Modes 

There are a number of available modes to choose from.

### chunk
Reads a file containing a number of prefixes.
The prefixes will be split into a given prefix size.
Further, prefixes larger than the given ping_prefix will be ignored and removed. 
Prefixes between these two sizes are added to the files.
All chunk files containing the split prefixes are written to the given output directory.

### loops
Reads a number of yarrp output files and analyses them.  
Produces an output project containing the found loops, routers within these loops and relevant prefixes.
If a file of routers is provided, further do an imperiled analysis.

### merge
Merges two projects from the loops module.

### p50analysis
Analyses multiple zmap output files and aggregates over the given full scan as well as over the persistent loops.

### p50targets
Creates a zmap compatible file for persistence scanning of a given list of prefixes.
Generation can be seeded via seed and file number.

### postloopstats
Generates additional information for a given project, including ASN attribution and other features.

### scatter
Distributes p50 target prefixes by sorting them in buckets.
In Round Robin fashion, the prefixes are taken from each bucket and used to create the resulting target list.

### target
Creates a usable list of IP addresses as targets from a given file containing prefixes.
Generation can be manually seeded for reproducible target generation.