#!/bin/bash
set -e

ollama serve &

sleep 5

ollama pull ${OLLAMA_MODEL:-llama3.2}

wait
