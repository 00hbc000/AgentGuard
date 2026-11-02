FROM python:3.14-slim
ARG AGENTGUARD_BUILD_TAG=dev
ENV AGENTGUARD_BUILD_TAG=$AGENTGUARD_BUILD_TAG
RUN apt-get update && apt-get install -y --no-install-recommends strace && rm -rf /var/lib/apt/lists/*
COPY run_skill.py execution.py canary.py agent_executor.py sink_server.py /opt/agentguard/
COPY guard/sitecustomize.py /opt/agentguard/guard/sitecustomize.py
ENTRYPOINT ["python", "/opt/agentguard/run_skill.py"]
