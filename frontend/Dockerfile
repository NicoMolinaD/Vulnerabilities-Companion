# Frontend Dockerfile
# Stage 1: Build
FROM node:18-alpine as build-stage

WORKDIR /app

COPY package*.json ./
RUN npm install

COPY . .
RUN npm run build

# Stage 2: Serve
FROM nginx:stable-alpine

# Copiar el build del frontend
COPY --from=build-stage /app/dist /usr/share/nginx/html

# Copiar configuración de Nginx
COPY nginx.conf /etc/nginx/conf.d/default.conf

EXPOSE 80

CMD ["nginx", "-g", "daemon off;"]
