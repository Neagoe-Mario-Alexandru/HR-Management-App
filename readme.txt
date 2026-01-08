Ce am facut pana acum:

- sistem de autentificare
- baza de date
- profilul utilizatorului
- sistemul de request/approve/reject concediu
- concurenta la approve/reject rezolvata cu approve/reject atomic
- anunt pe mail la request de leave, fie approve sau reject
- sa vada deconturile/cererile sale de concediu angajatul
- sistemul de deconturi, fara cheie de la Stripe, mock
- notificare atunci cand un decont isi ia reject sau approve
- rate limiting cu redis pe deconturi (maxim 5 pe zi, se reseteaza la miezul noptii)


De facut:
- implementat administrare prin Keycloak API
- de revazut in baza de date cum sunt stocati angajatii, vreau sa le stochez toate datele
sau restul de date sa mi le trag din Keycloak 