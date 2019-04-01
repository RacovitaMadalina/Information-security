Prezentarea minimala a pasilor pentru rularea temei:

	pasul 1) cmd: python Manager_Server.py
	pasul 2) cmd: python A.py "CFB" ("OFB" sau "CBC") ".................	\fisier.txt" (calea absoluta de la fisier)
	sau mai simplu: python A.py OFB fisier_regen.txt
			python A.py OFB fisier.txt
						s.a.m.d
	pasul 3) cmd: python B.py
	pasul 4) cmd: python C.py

Precizez ca versiunea de python folosita este Python 3.6.3

Diferenta dintre fisierele fisier.txt si fisier_regen.txt este aceea ca fisier_regen.txt are un continut mai mare, care va permite regenerarea cheilor de mai multe ori, pe cand fisier.txt are un continut mai mic, ce nu necesita o regenerare ulterioara a cheilor. Q este setat la valoarea default de 65 de blocuri.



