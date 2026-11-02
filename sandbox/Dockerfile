FROM python:3.14-slim
ARG AGENTGUARD_BUILD_TAG=dev
ENV AGENTGUARD_BUILD_TAG=$AGENTGUARD_BUILD_TAG
RUN apt-get update && apt-get install -y --no-install-recommends strace && rm -rf /var/lib/apt/lists/*
COPY run_skill.py /opt/agentguard/run_skill.py
COPY sink_server.py /opt/agentguard/sink_server.py
COPY agent_executor.py /opt/agentguard/agent_executor.py
ENTRYPOINT ["python", "/opt/agentguard/run_skill.py"]
