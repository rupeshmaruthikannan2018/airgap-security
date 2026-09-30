FROM eclipse-temurin:17-jre

ENV TOMCAT_VERSION=9.0.98
ENV CATALINA_HOME=/opt/tomcat
ENV PATH="${CATALINA_HOME}/bin:${PATH}"

WORKDIR /opt

RUN apt-get update \
    && apt-get install -y --no-install-recommends curl ca-certificates \
    && rm -rf /var/lib/apt/lists/*

RUN curl -fL \
    https://archive.apache.org/dist/tomcat/tomcat-9/v9.0.98/bin/apache-tomcat-9.0.98.tar.gz \
    -o /tmp/apache-tomcat-9.0.98.tar.gz

RUN echo "07d87286e8ee84bb291069c596cf36233e56a14e3ecb6d65eea0fa7c7042ce5e75f5db31f210b96b6b25b80b34e626dd26c5a6ed5c052384a8587d62658b5e16  /tmp/apache-tomcat-9.0.98.tar.gz" \
    | sha512sum -c -

RUN tar -xzf /tmp/apache-tomcat-9.0.98.tar.gz \
    && mv /opt/apache-tomcat-9.0.98 ${CATALINA_HOME} \
    && rm /tmp/apache-tomcat-9.0.98.tar.gz

RUN rm -rf ${CATALINA_HOME}/webapps/docs \
           ${CATALINA_HOME}/webapps/examples

EXPOSE 8080

CMD ["catalina.sh", "run"]