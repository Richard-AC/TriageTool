# TriageTool

Simple tool to triage crashes obtained from fuzzing. 

Usage: TriageTool.exe \<program path\> \<input dir\> \<output dir\> [\<extension\>]

Example: TriageTool.exe C:\myapp.exe C:\infolder C:\outfolder .pdf

# To do
- Find a better way to identify crashes uniquely 
- Automatically detect null derefs 