HR Management APP
Autor: Neagoe Mario-Alexandru
Grupa: 341C5


Timp estimativ de lucru: 40-50 de ore
(plus minus, nu am monitorizat foarte atent timpul din vacanta)


Overview roluri:

Angajat:
- Isi poate vedea profilul
- Poate face cereri de concediu/decont
- Primeste pe mail raspuns legat de cererile sale
- Poate vedea cererile sale de concediu/decont si statusul lor

HR:
- Isi poate vedea profilul
- Gestioneaza cererile de concediu
- Gestioneaza cererile de decont, ca sa ajunga cererea de decont la
Administrator trebuie mai intai sa primeasca aprobarea de la HR
- Poate vedea profilurile tuturor angajatilor

Administrator:
- Isi poate vedea profilul
- Poate gestiona deconturile aprobate de HR
- Gestioneaza cererile de concediu
- Poate vedea profilurile tuturor angajatilor
- Poate crea utilizatori noi, gestioneaza rolurile si poate sterge
utilizatori


Autentificare si autorizare:
- Autentificarea se face prin Keycloak (Single Sign-On)
- Protocol utilizat: OpenID Connect / OAuth2
- Accesul la API-uri este controlat prin JWT tokens
- Frontend-ul si microserviciile valideaza token-ul pentru autorizare
- Profilul utilizatorului este creat automat în baza de date locala la
primul login, folosind metadatele primite de la Keycloak
- Rolurile sunt gestionate prin Keycloak Admin API


Arhitectura:

- Aplicatia este bazata pe o arhitectura de tip microservicii, 
orchestrata printr-un API Gateway.

- Componente principale

- Keycloak – autentificare si managementul identitatii

- API Gateway – rutare cereri si rate limiting

-Profile Service – gestionarea profilurilor utilizatorilor

- Leave Service – gestionarea cererilor de concediu

- Expense Service – gestionarea cererilor de decont

- Payment Service – procesare plati/deconturi (asincron)

- Notification Service – trimitere notificari email

- Reporting Service – raportare si citire din replici de baza de date

- RabbitMQ – mesagerie între servicii

- Redis – rate limiting


Baza de dat
- Fiecare microserviciu foloseste o baza de date proprie (PostgreSQL)
- Persistenta este realizata folosind SQLAlchemy
- Structuri principale: users, leave_requests, expenses


Livrarea proiectului:
- Prin Docker Compose si Swarm


Fluxuri principale:
- Flux cerere concediu
- Angajatul trimite cererea de concediu
- HR primeste cererea si decide aprobarea sau respingerea
- Angajatul primeste notificare prin email cu rezultatul
- Flux cerere decont
- Angajatul trimite cererea de decont
- HR aproba sau respinge cererea
- Cererile aprobate de HR sunt trimise catre Administrator
- Administratorul decide aprobarea finala sau respingerea
- Angajatul este notificat prin email

Rate Limiting:
- Implementat folosind Redis
- Previne trimiterea abuziva de cereri de decont
- Exemplu regula: Maxim 5 cereri de decont / zi / utilizator

Tehnologii utilizate:
- Backend: Python
- ORM: SQLAlchemy
- Autentificare: Keycloak (OIDC / OAuth2)
- Mesagerie: RabbitMQ
- Cache / Rate limiting: Redis
- Baza de date: PostgreSQL
- Containerizare: Docker
- Orchestrare: Docker Compose / Docker Swarm

Comanda deploy:
docker stack deploy -c docker-compose.yml proiect_scd

Colectii + environments Postman:
Teste admin:
https://scd999.postman.co/workspace/SCD-PROIECT~e2eb423a-8213-45ee-8a67-54fc1ddd7866/collection/40824244-e16ece3e-039f-41c1-8137-c1b3147258d3?action=share&creator=40824244&active-environment=40824244-e7b24b98-9b8c-4edb-bb05-66d9e123f2a0