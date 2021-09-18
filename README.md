# TriageTool

Custom Windows userland debugger to triage crashes obtained from fuzzing. 
The goals is to generate a hash to identifying a given bug and group inputs causing the same bug together.  

Usage: TriageTool.exe \<program path\> \<input dir\> \<output dir\> [\<extension\>]

Example: TriageTool.exe C:\myapp.exe C:\infolder C:\outfolder .pdf

# To do
- Find a hashing function that creates larger hashes. The current one is only 16 bits. This limit is due to ASLR.  
- Automatically detect null derefs 