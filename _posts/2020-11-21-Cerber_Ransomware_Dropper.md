---
layout: post
title: Cerber Ransomware Dropper - Custom XOR routine with Regex, XOR and many charcodes
excerpt_separator: <!--more-->
---

Malware dropper utilising some interesting custom routines for obfuscating a final payload. Regex, XOR and charcodes. 


<!--more-->
# Cerber Ransomware Dropper

# Summary

The sample is a well obfuscated javascript file containing a large and heavily obfuscated string. Analysis of the base code indicates a custom decryption/decoding routine that extracts a primary payload. Once extracted, the code calls out to an attackers server and  retrieves a malicious executable binary. 

Analysis of the attackers domain using virustotal indicates that it once hosted cerber ransomware. 

The decryption routine utilises regex to extract hex values from an obfuscated string, which then undergo a interesting brute force and XOR operation to produce a second set of hex values, corresponding to ASCII characters. Once properly extracted, the second set of ascii values make up a payload that retrieves and loads a malicious binary. 

## Source File

The sample can be found here, in the HynekPetrak Javascript malware collection. 

![img](/resources/Images/2020-11-21/sourcefile.jpg)

## Initial Analysis

Analysis of the source file shows that it consists mostly of one large obfuscated string. 

Below that, there are some obfuscated function names, and a reference to a regex query. 

![img](/resources/Images/2020-11-21/initial_analysis.jpg)

In order to make any sense of this, I first focused on the large obfuscated block. I removed the joining plus signs and attempted to decode it using any common methods (base64, hex etc), but this was not of any success. 

Then I removed the block, and focused on the surrounding code, in order to get an idea as to how it is used. 

![img](/resources/Images/2020-11-21/image45)

This made me realise that the obfuscated block, is actually passed into another function later on in the code. Presumably, this second block where the code is passed, will contain the de-obfuscation routine. 

Adding some newlines for readability, this is where the obfuscated string ends up going. Note that there is an interesting regex function in there. 

![img](/resources/Images/2020-11-21/image55)

Rather than reading the obfuscated code, I took a guess at what the variable names might be, and used vscode search/replace to fix them up. 

![img](/resources/Images/2020-11-21/image444)

Note that the "getRandomChar()" function, is referencing this code previously defined in the function. Which seems to return a random character from the array in the function. 

![img](/resources/Images/2020-11-21/getchar)

At first, I thought these were just a bunch of meaningless characters, but eventually I realised that the possible values contain an XOR operator ^, and all the characters required to spell out "eval". This will make more sense later. 

![image-20201122174712441](/resources/Images/2020-11-21/eval)

On each iteration of the whole while loop, a random set of characters from the "getrandomchar" array will be returned to the "getRandomChar()" function calls.From what I can tell, these are truly random, which means that on most iterations, the function will be invalid. Eg when it becomes "peva(result)" and "p86". When this happens, the function will gracefully fail, and the error will be caught by the "catch(er)" statement. 

Then, the loop will iterate again and try the next set of random characters. Eventually landing on "^86"(XOR 86) and "eval(result)". Which will successfully decode the obfuscated string and execute the resulting code. 

Taking into account all of the above, the decryption routine does the following:

- Uses regex to grab substrings of length 7, from our original large obfuscated block. 
- Initiates an array to store the substrings. 
- Uses a while loop to iterate through the substrings and:
  - Extract the last 2 characters of each 7 length substring (if done properly, these will all be valid ascii char codes)
  - Converts the extracted ascii char codes into decimal integers. 
  - XOR's this integer with the decimal 86
  - Converts the XOR'd result into ASCII. 
  - Saves the result into a buffer
  - Executes the buffer

## Manual Decryption

I first copied the large obfuscated string into regex101, in order to test my theory about the 7 char strings and the last two values. 

![img](/resources/Images/2020-11-21/regex101)

These were the results, which confirmed the idea that the extracted values could be ascii char codes. 

![img](/resources/Images/2020-11-21/regex111)

I then used cyberchef to extract the charcodes, using the same regex as used in regex101. 

Note that I used three recipes, 

1. To remove whitespace for easier reading
2. To remove the plus signs and create one large string (instead of multiple concatenated strings)
3. Uses regex and find/replace to extract the final charcodes using capture groups. 
   1. Note the final regex query is (\S{5})(\S{2}), which utilises two capture groups. 
   2. Were only interested in the second one, hence the $2 in the replace value.

![img](/resources/Images/2020-11-21/charcodes111)

Alternatively, you could also make it "$2\n" in order to have newline'd output. 

![img](/resources/Images/2020-11-21/output1111)

I then tried to XOR this output using cyberchef, but for some reason it didn't work. It looked like cyber chef was trying to XOR the entire output as one piece, as opposed to XOR'ing each individual charcode. 

So instead, I decided to copy the output into a text file, and use a python script to perform the XOR operation. 

![img](/resources/Images/2020-11-21/output_text_file.jpg)

I was able to devise the following python script. 

![img](/resources/Images/2020-11-21/python_script_decoce)

Which when executed, produced the following output. If you look closely, this looks like valid javascript code (success!). 

![img](/resources/Images/2020-11-21/decoded1011)

So I copied and pasted the above output into cyberchef for round 2. 

### Second Round of De-obfuscation

I copied the output into cyberchef, and then used the "generic code beautify" and "syntax highlighter" functions to make the code more readable. 

Most of the code looks fairly standard, MSXML objects for url retrieval, and activexobjects for code execution and access to deeper (than standard javascript) functionality. 

If you look at the highlighted boxes, you can even see the attackers servers and extract them as IOC's

![img](/resources/Images/2020-11-21/second_round)

Based on the above and below, we can tell that the file's primary function is to retrieve a malicious executable file. 

We can also see the use of the math.random function for naming the file, so it won't have a predictable filename that can be used as an IOC. We can also see that it intends on saving the file to the windows temp folder. 

![img](/resources/Images/2020-11-21/dropper)

Eventually, we get to the end of the code, where we can see the use of wscript to access windows shell functionality, and utilise cmd.exe to execute the dropped payload. 
Interestingly, it also tries to delete the source .js file, as well as any other js files in the directory. 

![img](/resources/Images/2020-11-21/endcode.jph)

### Analysis of IOC Domains

Interestingly, the domains don't have that many detections on virustotal. 

![img](/resources/Images/2020-11-21/bad-domain)

![img](/resources/Images/2020-11-21/file2132132)



### Python Script

Here's a copy python script I made for extracting the second payload. 

```python
import re
import sys

f = open(sys.argv[1],"r")
data = f.readlines()

for line in data:
        if len(line) == 0:
                continue
        line = line.strip()
        x = int(line,16)
        x = x^86        

        
        print(chr(x),end="")
```

