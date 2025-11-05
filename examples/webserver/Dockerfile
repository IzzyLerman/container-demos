FROM nginx:latest
COPY ./nginx.conf /etc/nginx/nginx.conf
COPY ./public /usr/share/nginx/html
COPY ./images /usr/share/nginx/images
EXPOSE 80
CMD ["nginx", "-g", "daemon off;"]
