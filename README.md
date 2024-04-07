# Ghidra BOIL / BOP Function Detector

This repository contains an implementation of a static dataflow analysis algorithm that aims to replicate the results of "Finding Buffer Overflow Inducing Loops in Binary Executables" by Sanjay Rawat and Laurent Mounier. Their paper on the topic can be found here: https://ieeexplore.ieee.org/document/6258307.

# Using the Algorithm

This project is implemented as a Ghidra script written in Java. The Ghidra reverse engineering framework can be downloaded here: https://ghidra-sre.org/.
As well, this entire repository must be put into the ~/ghidra_scripts directory.
Before the algorithm can be run, the executable/object file/module that you want to perform the analysis on must be imported into a ghidra project.
The algorithm is designed to run in headless mode. It must be run from the <ghidra_installation_dir>/support directory. In this directory, you can run the algorithm on a desired object file belonging to the corresponding ghidra project as so:

```
./analyzeHeadless /path/to/ghidra/project -process object.o -postscript boil_detection_project.Analyzer
```

# Options

In the Analyzer.java class, the **VERBOSE_PRINT** boolean value can be changed to true to print additional information while the algorithm is running, such as full function P-code CFGs and recursive dependency chain calculation output.