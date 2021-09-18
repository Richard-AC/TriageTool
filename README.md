# TriageTool

Custom Windows userland debugger to triage crashes obtained from fuzzing. 
The goal is to generate a hash to identify a given bug and group inputs causing the same bug together.  

Usage: TriageTool.exe \<program path\> \<input dir\> \<output dir\> [\<extension\>]

Example: TriageTool.exe C:\myapp.exe C:\infolder C:\outfolder .pdf
