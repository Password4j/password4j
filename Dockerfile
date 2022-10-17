FROM maven:3.8.6-amazoncorretto-8

WORKDIR /build
ADD pom.xml /build/pom.xml
RUN mvn verify clean --fail-never

COPY . /build
RUN mvn clean package
