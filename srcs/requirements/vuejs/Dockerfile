FROM	debian:buster

RUN	apt-get update -y && apt-get install -y curl
RUN	curl -fsSL https://deb.nodesource.com/setup_16.x | bash -
RUN	apt-get install -y nodejs

WORKDIR	/app

COPY	conf/frontend .

RUN	npm install

EXPOSE	8080

CMD	["npm", "run", "dev", "--", "--port", "8080"]
