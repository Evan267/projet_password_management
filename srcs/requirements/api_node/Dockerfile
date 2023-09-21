FROM	debian:buster

RUN	apt-get update -y && apt-get install -y curl
RUN	curl -fsSL https://deb.nodesource.com/setup_16.x | bash -
RUN	apt-get install -y nodejs

WORKDIR	/app

COPY	conf/app/ .

RUN	npm install

EXPOSE	3000

CMD	["npm", "run", "prod"]
