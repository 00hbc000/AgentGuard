FROM python:3.14-slim
ARG AGENTGUARD_BUILD_TAG=dev
ENV AGENTGUARD_BUILD_TAG=$AGENTGUARD_BUILD_TAG
COPY sink_server.py canary.py /opt/agentguard/
ENTRYPOINT ["python", "/opt/agentguard/sink_server.py"]
