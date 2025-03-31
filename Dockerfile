FROM php:8.1-cli

RUN apt-get update && apt-get install -y \
    tshark \
    tcpdump \
    && rm -rf /var/lib/apt/lists/*

RUN docker-php-ext-install pdo pdo_mysql

WORKDIR /var/www/html

COPY . /var/www/html

EXPOSE 8101

CMD ["php", "-S", "0.0.0.0:8101", "-t", "/var/www/html"]
