# Information-security
Implementation for CFB, OFB, CBC within a communication protocol.

Prezentarea minimala a pasilor pentru rularea temei:

Pasul 1)  

    python Manager_Server.py

Pasul 2) 

    python A.py "CFB" ("OFB" sau "CBC") ".................	\fisier.txt" (calea absoluta de la fisier)
	  sau mai simplu: python A.py OFB fisier_regen.txt
		python A.py OFB fisier.txt      s.a.m.d
    
Pasul 3) 

    python B.py

Pasul 4) 

    python C.py

Precizez ca versiunea de python folosita este Python 3.6.3

Diferenta dintre fisierele fisier.txt si fisier_regen.txt este aceea ca fisier_regen.txt are un continut mai mare, care va permite regenerarea cheilor de mai multe ori, pe cand fisier.txt are un continut mai mic, ce nu necesita o regenerare ulterioara a cheilor. Q este setat la valoarea default de 65 de blocuri.
