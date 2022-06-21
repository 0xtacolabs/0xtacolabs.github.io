---
layout: post
title: Locky Ransomware Dropper - XOR Encoding, Regex, Scheduled Tasks
excerpt_separator: <!--more-->
---

Javascript-based Locky Ransomware Dropper that utilises Iterative XOR Encoding, Regex, Scheduled Tasks and registry keys. 

<!--more-->



## Locky Ransomware Dropper - Iterative XOR encoding, Regex and Scheduled Tasks



## Summary

The sample is a piece of obfuscated javascript code, utilising some interesting encoding/obfuscation techniques to hide it's final purpose of dropping a malicious binary. Once the Iterative XOR encryption and regex has been successfully "reversed", the payload is revealed to be a dropper for a malicious binary file. Likely, this file is Locky Ransomware (see note below). 



Although I was unable to connect to the domain to retrieve the binary payload, I was able to find references to the c2 domain in the below writeup  by blackberry. Which indicates that it has been used to host and deploy Locky Ransomware. 

https://blogs.blackberry.com/en/2017/11/threat-spotlight-locky-ransomware

Interesting Notes on the sample:

- Uses obfuscated variable/function names
- Customised encoding routine, no base64 or similar
- Brute forces it's own function definitions
- Utilises relatively clean domains for hosting payload
- Uses registry keys to check for victim current windows version
- Attempts to use scheduled tasks for execution.

## Indicators of Compromise

- http(s)://dboosajqn[.]top/1/
- dboosajqn[.]top

## Source File

https://github.com/HynekPetrak/javascript-malware-collection/blob/master/2017/20170321/20170321_d2bdd39119af20dbfc0c1822224b59ba.js

![image-20210112135815936](/resources/Images/2021-01-12/image-20210112135815936.png)



## Initial Overview

Initial overview of the code shows a small function that takes an input, and converts it to base16. 
And another function that contains and returns a large obfuscated string, likely the main payload. 

![image-20210111170248872](/resources/Images/2021-01-12/image-20210111170248872.png)

Below the main obfuscated string, the following functions can be seen. 

The Third function looks the most interesting. 

![image-20210111171035939](/resources/Images/2021-01-12/image-20210111171035939.png)

Since all three "sections" will need to be analysed. I'll break them up and analyse one by one. 

![image-20210112220350496](/resources/Images/2021-01-12/image-20210112220350496.png)

### Code Piece 1 - Random Character Generator

The code from lines 31-35 look like this. 

- Line 33 converts the string into an array, with each array value containing a single letter/char
  - This is done by using regex to extract non-whitespace values (of length 1), using \S{1]}
- line 34 grabs a random char value from this array. Using a random number generator. 

TLDR: This is a random character generator
Take special note of the possible return values, which contain a "+" and "eval"

![image-20210112220432572](/resources/Images/2021-01-12/image-20210112220432572.png)

Since we know that kleoonfkcw() is a random character generator, we can ctrl+f and replace all references with "randomChar" or anything similar. 

The code will now look like

![image-20210112223512118](/resources/Images/2021-01-12/image-20210112223512118.png)



### Code Piece 2 - base16 converter

On lines 36-39, we have the following code, which simply uses parseInt to convert an input number to base16 (HEX)

![image-20210112221607938](/resources/Images/2021-01-12/image-20210112221607938.png)

Fixing this up, the code will now look like the following. 

![image-20210112221753250](/resources/Images/2021-01-12/image-20210112221753250.png)



### Section 3 - De-obfuscation Routine

Based on below, this function serves as the primary de-obfuscation routine for the giant string declared previously in the code. 

T

![image-20210112223728254](/resources/Images/2021-01-12/image-20210112223728254.png)

Looking closely, we can see where the obfuscated string ends up going. 

![image-20210112222448134](/resources/Images/2021-01-12/image-20210112222448134.png)

In order to make more sense of the function, I took it out of the string and put it into a new doc. 

Which looks like this. Note the references to randomChar(). Which will populate the function logic with a value from "yvla+e_"

It's not very obvious at first glance, but this will eventually populate the values with "+" and "eval"

Thus creating a "+=" on line 6, and "eval" on line 9.



![image-20210112224020150](/resources/Images/2021-01-12/image-20210112224020150.png)

Since the function is being defined dynamically inside of an infinite loop, eventually the values will line up below, allowing the code to execute. 

![image-20210112224637709](/resources/Images/2021-01-12/image-20210112224637709.png)

![image-20210112224439232](/resources/Images/2021-01-12/image-20210112224439232.png)

Cleaning up a bit more, the de-obfuscation code looks like this. 

![image-20210112225001242](/resources/Images/2021-01-12/image-20210112225001242.png)

With functions and variables renamed, looks more like this. 

![image-20210112225204320](/resources/Images/2021-01-12/image-20210112225204320.png)

The logic above is fairly simple, and can be recreated as a python script below. 
Alternatively, the code could easily be executed with a print/echo within javascript, but I like to use python. 

### De-obfuscation Script - Payload Extracted

![image-20210112144924765](/resources/Images/2021-01-12/image-20210112144924765.png)

The output is a bit messy, so I used cyberchef to add some newlines/spacing for readability.

![image-20210112145057900](/resources/Images/2021-01-12/image-20210112145057900.png)



I then moved it into vscode, since I like the interface and highlighting better. 

See below for a quick snippet.

![image-20210112225505324](/resources/Images/2021-01-12/image-20210112225505324.png)



## Analysis of Final Payload

Looking at the final payload, it can be seen that the malware uses XMLHTTP objects for sending http requests and retrieving the final binary payload. 

![image-20210112145843645](/resources/Images/2021-01-12/image-20210112145843645.png)

Below we can see the URL/Domain where the malware is retrieved from. 

![image-20210112151007605](/resources/Images/2021-01-12/image-20210112151007605.png)

Below we can see that the malware gets the location of the current users temp folder, and generates a 7 digit filename for the dropped binary. 

![image-20210112151158403](/resources/Images/2021-01-12/image-20210112151158403.png)

Below it can be seen that the malware does a few interesting things.

- Checks the registry, to make sure that the victim PC is running windows 6.0 (Vista) or above
- Attempts to create a scheduled task to execute the malware
  - Interestingly, only sets the malware to execute once (based on the /sc once) parameter
  - Names the task a 7 digit value, eg 3482888. Doesn't try to masquerade as something legitimate. 
  - Uses the previously grabbed time value to execute the code at current time + 2 minutes. 
- If the scheduled task creation fails, launches the malware directly using cmd.exe

![image-20210112230616787](/resources/Images/2021-01-12/image-20210112230616787.png)



## Analysis of Malware Domain/IOC

Below we can see 

![image-20210112155433237](/resources/Images/2021-01-12/image-20210112155433237.png)





Also interesting is that the domain itself is relatively clean. 

![image-20210112155902241](/resources/Images/2021-01-12/image-20210112155902241.png)

The domain is also mentioned in this writeup of Locky Ransomware. Indicating that Locky Ransomware could be contained in the dropped binary payload. 

https://blogs.blackberry.com/en/2017/11/threat-spotlight-locky-ransomware

![image-20210112212533445](/resources/Images/2021-01-12/image-20210112212533445.png)



## 

## Python Script

```python
#Python Script used for decoding, slightly modified from the previous screenshot
#Mostly just changes for readability

bad_code = "9228379b1840edabf<<SNIPPED>>adfaa82a4bfbdf104f2c30badf7d7bd8435af6e5f95d41352d938877a573744c1a46c08caaedf37f18b8d1325b3670b897303dd60951e7e5f41e4a662b879457ec3c314e014bc494b1a1b37516b39e144d3078b2912f2b971e00a2bea600173c649b9b0af7"

#array of integers used for XOR operations
Arr1 = [244,93,89,248,108,41,130,197,219,125,106,21,95,230,230,35,204,30,17,101,33,59,165,224,217,136,136,8,107,208,255,96,46,88,88,154]
#extracts hex values from the main string, stores them as a list
#The \S{2} will extract all non-whitespace values of length two
Hex_Values = re.findall("\S{2}", bad_code)

result = "", counter1 = 0, counter2 = 0
#while loop that recreates the de-obfuscation logic
while (counter1 < len(Hex_values)):
    
    #resets the XOR array if loop has reached the end
    if (counter2 >= len(Arr1)):
        counter2 = 0
    #XORS the extracted hex value, with a value from the XOR array
    num = int(Hex_Values[counter1], 16)^Arr1[counter2]
    #returns the ascii value of the XOR result
    result += chr(num)
    counter1 += 1
    counter2 += 1

print(result)

```

