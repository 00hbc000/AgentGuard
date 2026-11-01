FROM python:3.14-slim
COPY sink_server.py /opt/agentguard/sink_server.py
ENTRYPOINT ["python", "/opt/agentguard/sink_server.py"]
