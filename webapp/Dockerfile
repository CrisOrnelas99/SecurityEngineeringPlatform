FROM node:20-alpine

WORKDIR /app

COPY package*.json ./
RUN apk add --no-cache python3 make g++ \
 && npm install --omit=dev \
 && apk del python3 make g++

COPY src ./src
COPY data ./data

RUN mkdir -p /app/logs /app/uploads

EXPOSE 3000
CMD ["npm", "start"]
