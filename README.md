The project was initiated by Marion Marschalek (G-data) and Raphaël Vinot (CIRCL) for a prensentation at Troopers called
[](https://www.troopers.de/events/troopers16/599_the_kings_in_your_castle_-_all_the_lame_threats_that_own_you_but_will_never_make_you_famous/).

The idea is to use the data stored and classified in MISP in order to derivate trends and uncoder correlations between events.

# Introduction

This repository contains scripts to process data from MISP and help analyse the outputs.


# Content

The scripts are sorted by usage, look at the readme files in the sub-directories.


## Files

* hashes-extract.sh: Extract all the hashes from JSON dumps.

## Directories

* groupping: makes groups of hashes and dump correlations.
* standalone: import all the indicators in a sqlite database
