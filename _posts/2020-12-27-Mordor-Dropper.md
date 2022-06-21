---
layout: post
title: Mordor Ransomware Dropper - Obfuscated Javascript with Hidden Payloads
excerpt_separator: <!--more-->
---

Javascript Malware Dropper that retrieves and executes a Mordor Ransomware payload. Utilises a few basic anti-automation techniques. 


<!--more-->


# Mordor Ransomware Dropper with Multiple Layers on Encoding

# Summary

The sample is a piece of obfuscated javascript code that retrieves and launches/executes a malicious executable from an attacker controlled server. The code utilises a few simple anti-sandbox techniques, and is well obfuscated in that all malicious commands are not visible in the initial code, and require successful reverse-engineering of the decoding routine in order to analyse. 

Based on the below article and analysis of the attacker controlled domain, the file was likely used to retrieve Mordor Ransomware. 

https://www.malware-traffic-analysis.net/2017/05/02/index.html



# Indicators of Compromise IOC's

| IOC                             | Severity |
| ------------------------------- | -------- |
| kingzoneg[.]top/admin.php?f=404 | High     |
| %TEMPLATES%\\d{4,6}\.exe$       | High     |
| kingzoneg[.]top/admin.php       | High     |
| kingzoneg[.]top                 | Medium   |
| 47.91[.]93.208                  | Medium   |
| 47.91[.]93.208/admin.php        | High     |




## Source File

The javascript file is from the HynekPetrak Javascript Malware Collection.

https://github.com/HynekPetrak/javascript-malware-collection/blob/master/2017/20170501/20170501_018edd4b581516682574e305c835c5c9.js

![image-20201226172020876](/resources/Images/2020-12-27/image-20201226172020876.png)

## Analysis

The code starts with a few variables created by concatenating/combining lots of small strings. This makes the code slightly more difficult to read, but is trivial to fix and remove.

![image-20201226174008720](/resources/Images/2020-12-27/image-20201226174008720.png)



There is a small function that appears to be a simple decoding routine. 
Although it breaks up the string into an array before rejoining, the code is essentially a search and replace. 



![image-20201226172748281](/resources/Images/2020-12-27/image-20201226172748281.png)

There are a few variables where the results of the decoded strings are stored, and some variables that store the results of those decoded strings being executed via eval. 

![image-20201226173054150](/resources/Images/2020-12-27/image-20201226173054150.png)



The code finishes with two eval statements, both on the results of decoded strings. 
Interestingly, the second eval performs the decoding twice, and also performs a check against a value not present in the initial code. 
Likely, this checked value is defined in one of the obfuscated strings and eval statements.

![image-20201226173642051](/resources/Images/2020-12-27/image-20201226173642051.png)

## Reverse Engineering

Now that there's a general understanding of the malware structure, the code can be analysed and decoded using cyberchef. 

First job is to fix up the "broken" strings, this can easily be done using find/replace and regex. 

- \\+? looks for plus signs at the beginning or end of the line
- \["'\] Looks for starting and ending quotes
- \\+\\n looks for a plus sign followed by a newline
- \\+?



![image-20201226185915303](/resources/Images/2020-12-27/image-20201226185915303.png)

Which can now be copy/pasted into vscode in a much more readable format. 

(Note that you can ctrl+shift+p, change language mode, javascript - to enable highlighting without saving as a file

![image-20201226190020160](/resources/Images/2020-12-27/image-20201226190020160.png)



Now it's time to rename some functions and variable names, anything that makes sense will do. 

![image-20201226190649713](/resources/Images/2020-12-27/image-20201226190649713.png)

The results \*could\* look like this. 

![image-20201226191140588](/resources/Images/2020-12-27/image-20201226191140588.png)



# Manual Decoding

bad_string1

## Bad_String1

For bad_string1, the value "ynXYUuwtAvWkxfpMbeqGZTrgFNVHmL" is used as a delimiter to create an array, the array is then concatenated back into a string, with a blank value used to join the values. 

Despite the use of arrays and joins, the routine is essentially a search and replace. 

![image-20201226191635426](/resources/Images/2020-12-27/image-20201226191635426.png)

Cyberchef can be used to decode the string. 

![image-20201226192121796](/resources/Images/2020-12-27/image-20201226192121796.png)

Observing the output, we can see that the code creates some activexobjects for executing shell commands and interacting with the filesystem. 

After this, the code checks if the hardcoded value "qxkFASizeYvpD1TcG" exists as a folder on the system. 
Not entirely sure what this is, but I think it may act as a basic protection against automated sandbox analysis, since the final payload will not execute if the value is true, and many sandboxes may provide dummy values in order to "satisfy" the code. 

See below that this value is later used to decide whether to execute a string, presumably the final payload. 

![image-20201226195144592](/resources/Images/2020-12-27/image-20201226195144592.png)

## bad_string2

bad_string2 only appears once in the initial code, it does not appear to be referenced anywhere else. 

Either it is junk code used to throw off analysis, or the value is used later by code contained in one of the obfuscated strings. 

![image-20201226195808679](/resources/Images/2020-12-27/image-20201226195808679.png)

## bad_string3

the bad_string3 decoding routine looks extremely similar to the routine for bad_string1. 

![image-20201226200034294](/resources/Images/2020-12-27/image-20201226200034294.png)

Using the same find/replace style approach used in bad_string1, the following payload was retrieved. 
Interesting, it references values obtained from bad_string1, and appears to use them to decode bad_string2, using a different routine to that used for bad_string1 and 3. 

![image-20201226200854138](/resources/Images/2020-12-27/image-20201226200854138.png)

Based on the above, it looks like bad_string2 is an obfuscated registry key. 
The rest of the code seems to use the previously defined wscript.shell object to  check the value of a registry key, and then retrieves the second character of the resulting registry key value. 

The registry key is contained within the bad_string2 variable, so it must be decoded to find out what key is being checked. 

### Decoding bad_string2

![image-20201226201648767](/resources/Images/2020-12-27/image-20201226201648767.png)

![image-20201226202158586](/resources/Images/2020-12-27/image-20201226202158586.png)

![image-20201226202343045](/resources/Images/2020-12-27/image-20201226202343045.png)

Whats interesting, is that this doen't even retrieve the "C" value as you might expect, it actually retrieves the ":" colon value. 


## bad_string4



![image-20201226202911455](/resources/Images/2020-12-27/image-20201226202911455.png)

![image-20201226203226800](/resources/Images/2020-12-27/image-20201226203226800.png)



Based on the above notes, there needs to be two rounds of decoding for bad_string4. 

- One round where ":" is replaced with "%". 
- One round where the "kpXvqnzVlFrDNceAHYhufwCxPUsiJo" value is replaced with "e"

![image-20201226203421324](/resources/Images/2020-12-27/image-20201226203421324.png)

Now note that the end result contains url encoded characters. So these will need to be removed to extract the final payload. 

For readability sake, I've copied the output (between the quotes) into a new cyberchef window. 

![image-20201226203734294](/resources/Images/2020-12-27/image-20201226203734294.png)

The decoding was successful, and the final payload has now been extracted. 

## Final Payload Analysis

The final payload is an executable malware dropper. It utilises:

- shell objects to execute shell commands on the system
- XMLHTTP Objects for performing HTTP queries
- ADODB.Stream objects for interacting with the resulting HTTP Streams
- The "templates" special folder for saving the dropped executable
- math.random for generating random executable names

![image-20201226204429913](/resources/Images/2020-12-27/image-20201226204429913.png)



# Virustotal Analysis of Domain/IOC

The exact URL has 5/66 detections on virustotal, and was first observed in May 2019. 

![image-20201226204812068](/resources/Images/2020-12-27/image-20201226204812068.png)

Interestingly, the domain itself only has 3 detections

![image-20201226205008133](/resources/Images/2020-12-27/image-20201226205008133.png)

There are quite a few subdomains. All resolving to IP's owned by AliBaba. 

![image-20201226205127622](/resources/Images/2020-12-27/image-20201226205127622.png)

![image-20201226205654022](/resources/Images/2020-12-27/image-20201226205654022.png)
