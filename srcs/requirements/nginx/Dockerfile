FROM debian:buster

RUN apt update -y \
	&& apt upgrade -y \
	&& apt install nginx -y \
	&& apt install openssl -y

RUN mkdir -p etc/nginx/ssl

RUN openssl req -x509 -nodes -out /etc/nginx/ssl/certificat.crt -keyout /etc/nginx/ssl/certificat.key -subj "/C=FR/ST=HR/L=Montreux-Jeune/O=chezmoi/OU=chezmoi/CN=test.com/UID=eberger"

RUN chmod 755 /var/www/html

RUN chown -R www-data:www-data /var/www/html

COPY conf/nginx.conf /etc/nginx/nginx.conf

EXPOSE 443

CMD [ "nginx", "-g", "daemon off;"]
