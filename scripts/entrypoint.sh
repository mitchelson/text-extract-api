#!/bin/bash

PYPROJECT_HASH_FILE=".pyproject.hash"
CURRENT_HASH=$(sha256sum pyproject.toml | awk '{ print $1 }')

if [ ! -d ".dvenv" ] || [ ! -f "$PYPROJECT_HASH_FILE" ] || [ "$(cat $PYPROJECT_HASH_FILE)" != "$CURRENT_HASH" ]; then
   echo "Dependencies have changed or .dvenv is missing. Reinstalling..."
   python -m venv .dvenv
   source .dvenv/bin/activate
   pip install --upgrade pip setuptools
   pip install .
   echo "$CURRENT_HASH" >"$PYPROJECT_HASH_FILE"
else
   python3 -m venv --upgrade /app/.dvenv # temporary :(
   echo "Virtual environment is up to date."
fi

source .dvenv/bin/activate

if [ "$APP_TYPE" = "celery" ]; then
   echo "Starting Celery worker..."
   exec celery -A text_extract_api.celery_app worker --loglevel=info --pool=solo
else
   echo "Pulling LLM models, please wait until this process is done..."
   python client/cli.py llm_pull --model llama3.1
   python client/cli.py llm_pull --model llama3.2-vision
   python client/cli.py llm_pull --model minicpm-v
   echo "LLM models are ready!"

   echo "Starting FastAPI app..."

   if [ "$APP_ENV" = "production" ]; then
      exec uvicorn text_extract_api.main:app --host 0.0.0.0 --port 8000
   else
      exec uvicorn text_extract_api.main:app --host 0.0.0.0 --port 8000 --reload
   fi
fi
