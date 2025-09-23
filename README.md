# GreenLoop
GreenLoop is a sustainable fashion platform that connects people who want to donate or consign their pre-loved clothes with those in need of affordable, quality fashion items.  
The project aims to reduce textile waste, promote a circular economy, and make clothing accessible to everyone through an online marketplace experience.

# Description
GreenLoop provides a seamless platform for clothing donation and consignment.  
Users can easily donate clothes they no longer use, or consign items in good condition for resale.  
Donated items are made available to people in need, while consigned items are displayed in an e-commerce style marketplace at affordable prices. 

---

# Tech Stack:
- Java 17
- Spring Boot 3.4.9
- Spring Cloud 2024.0.2
- MySQL
- RabbitMQ
- Redis

# CommandLine
    - docker exec -it greenloop-redis redis-cli
    - KEYS bl:*
    - docker run -d --name greenloop-redis -p 6379:6379 redis:7.2-alpine
