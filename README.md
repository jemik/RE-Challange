# RE-Challange
 ###### Reverse engineering challange: APT0.5 AkA FluffyPenguins

You are the Senior security analyst at SecretSource.CO One of your team members has investigated an incident and uncovered a stealthy threat hidden in memory on your company servers.
Your colleague suspects that it’s the APT group called FluffyPenguins, based on the TTP's he discovered.

This is not the first time you have encountered FluffyPenguins and in previous incidents you discovered a pattern that seems to identify their tool of choice.




**Patterns:**
```
00 00 51 66 4F 46 7A 56 6C 68 47 56 79 42 6A 52 68 4A 56 59 00 74 33 5A 68 78 6D 5A

00 00 51 66 4F 46 7A 56 6C 68 00 56 79 42 6A 52 68 4A 56 00 5A 74 33 5A 68 78 6D 5A

00 00 51 66 4F 46 7A 56 6C 68 47 56 00 42 6A 52 00 4A 56 59 5A 74 33 5A 68 78 6D 5A

00 00 51 66 4F 46 7A 00 6C 68 47 56 79 42 6A 00 68 4A 56 59 00 74 33 5A 68 78 6D 5A
```


Your team member managed to dump process memory of a suspicious binary running on one of the servers. 
So, based on what you already know you start to analyze the memory.


Is this FluffyPenguins? 

Find the flag in the memory dump.


**happy hunting...**