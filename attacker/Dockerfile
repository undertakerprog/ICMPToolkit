FROM python:3.11-slim
WORKDIR /app
COPY ../ping_tool.py .
RUN apt-get update && apt-get install -y iputils-ping tcpdump
CMD ["bash"]
