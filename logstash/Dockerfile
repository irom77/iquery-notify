FROM logstash:5

# Add your logstash plugins setup here
# RUN logstash-plugin install logstash-filter-de_dot
# Example: RUN logstash-plugin install logstash-filter-json
RUN logstash-plugin install logstash-output-influxdb logstash-output-email logstash-output-exec

COPY ./config/* /etc/logstash/conf.d/
COPY ./exec/* /usr/local/bin/

CMD ["logstash", "-f", "/etc/logstash/conf.d/"]